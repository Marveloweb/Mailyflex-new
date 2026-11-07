import { describe, expect, it } from 'vitest';
import { StaticResolver } from '../src/dns.ts';
import { analyzeSpf, chunkHost, flattenSpf, parseSpf, toTxtStrings } from '../src/spf.ts';
import { compactCidrs, ipInCidr } from '../src/ip.ts';

describe('parseSpf', () => {
  it('parses mechanisms, qualifiers and cidrs', () => {
    const p = parseSpf('v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 a mx:mail.example.com/24//64 include:_spf.google.com ~all');
    expect(p.valid).toBe(true);
    expect(p.terms).toHaveLength(6);
    const mx = p.terms[3];
    expect(mx).toMatchObject({ name: 'mx', value: 'mail.example.com', cidr4: 24, cidr6: 64 });
    expect(p.terms[5]).toMatchObject({ name: 'all', qualifier: '~' });
  });

  it('rejects bad records', () => {
    expect(parseSpf('v=spf2 a').valid).toBe(false);
    expect(parseSpf('v=spf1 ip4:300.1.1.1 -all').errors[0]).toMatch(/not a valid IPv4/);
    expect(parseSpf('v=spf1 foo:bar -all').errors[0]).toMatch(/Unknown term/);
    expect(parseSpf('v=spf1 include -all').errors[0]).toMatch(/needs a domain/);
    expect(parseSpf('v=spf1 redirect=a.com redirect=b.com').valid).toBe(false);
  });

  it('warns about ptr and terms after all', () => {
    const p = parseSpf('v=spf1 ptr -all a');
    expect(p.warnings.join(' ')).toMatch(/ptr/);
    expect(p.warnings.join(' ')).toMatch(/after "all"/);
  });
});

const zone = new StaticResolver({
  'TXT example.com': ['v=spf1 include:_spf.google.com include:sendgrid.net ip4:192.0.2.10 -all', 'google-site-verification=abc'],
  'TXT _spf.google.com': ['v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all'],
  'TXT _netblocks.google.com': ['v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all'],
  'TXT _netblocks2.google.com': ['v=spf1 ip6:2001:4860:4000::/36 ~all'],
  'TXT sendgrid.net': ['v=spf1 ip4:167.89.0.0/17 ip4:167.89.128.0/17 ~all'],
  'TXT toomany.com': ['v=spf1 ' + Array.from({ length: 11 }, (_, i) => `include:s${i}.toomany.com`).join(' ') + ' -all'],
  ...Object.fromEntries(Array.from({ length: 11 }, (_, i) => [`TXT s${i}.toomany.com`, [`v=spf1 ip4:10.0.${i}.0/24 -all`]])),
  'TXT two.com': ['v=spf1 -all', 'v=spf1 mx -all'],
  'TXT loop.com': ['v=spf1 include:loop2.com -all'],
  'TXT loop2.com': ['v=spf1 include:loop.com -all'],
  'TXT voids.com': ['v=spf1 a:nx1.voids.com a:nx2.voids.com a:nx3.voids.com -all'],
  'TXT mx.com': ['v=spf1 mx -all'],
  'MX mx.com': ['10 mail.mx.com'],
  'A mail.mx.com': ['203.0.113.5'],
  'TXT macro.com': ['v=spf1 include:%{i}._spf.macro.com exists:%{i}.x.macro.com -all'],
  'TXT plusall.com': ['v=spf1 +all'],
});

describe('analyzeSpf', () => {
  it('counts nested lookups and collects IPs', async () => {
    const r = await analyzeSpf('example.com', zone);
    expect(r.status).toBe('ok');
    expect(r.lookupCount).toBe(4); // google, netblocks, netblocks2, sendgrid
    expect(r.ip4).toContain('167.89.0.0/16'); // two /17s merged
    expect(r.ip4).toContain('192.0.2.10');
    expect(r.ip6).toEqual(['2001:4860:4000::/36']);
    expect(r.allQualifier).toBe('-');
    expect(r.tree?.children.map((c) => c.domain)).toEqual(['_spf.google.com', 'sendgrid.net']);
  });

  it('flags more than 10 lookups', async () => {
    const r = await analyzeSpf('toomany.com', zone);
    expect(r.lookupCount).toBe(11);
    expect(r.status).toBe('invalid');
    expect(r.errors.join(' ')).toMatch(/11 of 10/);
  });

  it('flags multiple records, missing record, loops, voids, +all', async () => {
    expect((await analyzeSpf('two.com', zone)).status).toBe('multiple');
    expect((await analyzeSpf('none.com', zone)).status).toBe('missing');
    expect((await analyzeSpf('loop.com', zone)).errors.join(' ')).toMatch(/Loop/);
    const v = await analyzeSpf('voids.com', zone);
    expect(v.voidCount).toBe(3);
    expect(v.errors.join(' ')).toMatch(/return nothing/);
    expect((await analyzeSpf('plusall.com', zone)).errors.join(' ')).toMatch(/\+all/);
  });

  it('resolves mx mechanism to addresses', async () => {
    const r = await analyzeSpf('mx.com', zone);
    expect(r.ip4).toEqual(['203.0.113.5']);
    expect(r.lookupCount).toBe(1);
  });

  it('keeps macros and exists as unflattenable', async () => {
    const r = await analyzeSpf('macro.com', zone);
    expect(r.unflattenable).toEqual(['include:%{i}._spf.macro.com', 'exists:%{i}.x.macro.com']);
  });

  it('analyzes an override record (generator preview)', async () => {
    const r = await analyzeSpf('preview.com', zone, { recordOverride: 'v=spf1 include:sendgrid.net ~all' });
    expect(r.lookupCount).toBe(1);
    expect(r.status).toBe('ok');
  });
});

describe('flattening', () => {
  it('compacts CIDRs', () => {
    expect(compactCidrs(['10.0.0.0/25', '10.0.0.128/25', '10.0.0.5', '10.0.1.0/24'], 4)).toEqual(['10.0.0.0/23']);
    expect(compactCidrs(['2001:db8::/33', '2001:db8:8000::/33'], 6)).toEqual(['2001:db8::/32']);
    expect(ipInCidr('167.89.200.1', '167.89.0.0/16')).toBe(true);
  });

  it('chains records under the byte limit', () => {
    const ips = Array.from({ length: 60 }, (_, i) => `198.51.${i}.7`);
    const recs = flattenSpf(ips, [], { baseHost: 'example.com._s.dns.mailyflex.com' });
    expect(recs.length).toBeGreaterThan(1);
    for (const r of recs) expect(r.value.length).toBeLessThanOrEqual(450);
    expect(recs[0]!.host).toBe('example.com._s.dns.mailyflex.com');
    expect(recs[1]!.host).toBe('example.1.com._s.dns.mailyflex.com'.replace('example.1.com', 'example.1.com'));
    expect(recs[0]!.value).toContain(`include:${chunkHost('example.com._s.dns.mailyflex.com', 1)}`);
    expect(recs.at(-1)!.value).not.toContain('include:');
    const all = recs.flatMap((r) => r.value.split(' ').filter((t) => t.startsWith('ip4:')));
    expect(all).toHaveLength(60);
  });

  it('splits long TXT values into 255-byte strings', () => {
    const v = 'v=spf1 ' + 'x'.repeat(600);
    const s = toTxtStrings(v);
    expect(s.match(/"/g)).toHaveLength(6);
  });
});
