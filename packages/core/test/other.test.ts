import { describe, expect, it } from 'vitest';
import { gzipSync, strToU8, zipSync } from 'fflate';
import { StaticResolver, expandIPv6, isValidDomain, normalizeDomain, parseTxtData, reverseIpName, DohResolver } from '../src/dns.ts';
import { analyzeDkim, parseDkimKey, rsaKeyBits } from '../src/dkim.ts';
import { analyzeBimi, analyzeMtaSts, analyzeMx, analyzeTlsRpt, buildMtaStsPolicy, mxMatchesPattern, parseMtaStsPolicy } from '../src/transport.ts';
import { analyzeBlacklists, checkIpBlocklists } from '../src/blacklist.ts';
import { identifySender, lookupIpIntel } from '../src/senders.ts';
import { parseAggregateReport, summarizeRecords, unpackReport, ReportParseError } from '../src/report.ts';
import { buildSpf } from '../src/generators.ts';
import { ENFORCEMENT_LADDER, nextStep, readiness, stepIndex } from '../src/enforcement.ts';
import { analyzeDmarc } from '../src/dmarc.ts';
import { GOOGLE_REPORT_XML, RFC9990_REPORT_XML, rsaSpki } from './fixtures.ts';

describe('dns helpers', () => {
  it('normalizes and validates domains', () => {
    expect(normalizeDomain(' https://WWW.Example.com/path?x ')).toBe('www.example.com');
    expect(normalizeDomain('user@Example.com.')).toBe('example.com');
    expect(isValidDomain('example.com')).toBe(true);
    expect(isValidDomain('localhost')).toBe(false);
    expect(isValidDomain('-bad.com')).toBe(false);
    expect(isValidDomain('xn--bcher-kva.example')).toBe(true);
  });

  it('parses TXT data strings', () => {
    expect(parseTxtData('"v=spf1 ip4:1.2.3.4 " "-all"')).toBe('v=spf1 ip4:1.2.3.4 -all');
    expect(parseTxtData('"say \\"hi\\" \\059"')).toBe('say "hi" ;');
    expect(parseTxtData('unquoted')).toBe('unquoted');
  });

  it('reverses IPs', () => {
    expect(reverseIpName('192.0.2.1')).toBe('1.2.0.192');
    expect(expandIPv6('2001:db8::1')).toBe('2001:0db8:0000:0000:0000:0000:0000:0001');
    expect(reverseIpName('2001:db8::1')!.startsWith('1.0.0.0.')).toBe(true);
  });

  it('DohResolver parses JSON answers, follows CNAME and falls back on failure', async () => {
    const calls: string[] = [];
    const fake: typeof fetch = async (input) => {
      const url = String(input);
      calls.push(url);
      if (url.startsWith('https://bad')) return new Response('nope', { status: 500 });
      return new Response(
        JSON.stringify({
          Status: 0,
          Answer: [
            { name: '_dmarc.x.com.', type: 5, TTL: 60, data: 'x.com._d.dns.mailyflex.com.' },
            { name: 'x.com._d.dns.mailyflex.com.', type: 16, TTL: 60, data: '"v=DMARC1; p=reject"' },
          ],
        }),
      );
    };
    const r = await new DohResolver({ endpoints: ['https://bad/dns', 'https://good/dns'], fetchImpl: fake }).query('_dmarc.x.com', 'TXT');
    expect(calls).toHaveLength(2);
    expect(r.status).toBe('NOERROR');
    expect(r.cnameTarget).toBe('x.com._d.dns.mailyflex.com');
    expect(r.answers[0]!.data).toBe('v=DMARC1; p=reject');
  });
});

describe('dkim', () => {
  it('measures RSA key sizes', async () => {
    expect(rsaKeyBits(await rsaSpki(2048))).toBe(2048);
    expect(rsaKeyBits(await rsaSpki(1024))).toBe(1024);
    expect(rsaKeyBits('not-base64!')).toBeNull();
  });

  it('parses key records', async () => {
    const k1024 = await rsaSpki(1024);
    const p = parseDkimKey(`v=DKIM1; k=rsa; p=${k1024}`);
    expect(p.valid).toBe(true);
    expect(p.keyBits).toBe(1024);
    expect(p.warnings[0]).toMatch(/2048/);
    expect(parseDkimKey('v=DKIM1; p=').revoked).toBe(true);
    expect(parseDkimKey('v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=').keyBits).toBe(256);
    expect(parseDkimKey('v=DKIM1; t=y; p=' + k1024).testing).toBe(true);
  });

  it('discovers selectors including custom ones', async () => {
    const k = await rsaSpki(2048);
    const zone = new StaticResolver({
      'TXT google._domainkey.example.com': [`v=DKIM1; k=rsa; p=${k}`],
      'TXT custom42._domainkey.example.com': [`v=DKIM1; p=${k}`],
      'TXT example.com': ['v=spf1 -all'],
    });
    const r = await analyzeDkim('example.com', zone, ['custom42']);
    expect(r.status).toBe('ok');
    expect(r.selectors.map((s) => s.selector).sort()).toEqual(['custom42', 'google']);
    const none = await analyzeDkim('example.com', new StaticResolver({ 'TXT example.com': ['x'] }));
    expect(none.status).toBe('missing');
  });
});

describe('transport checks', () => {
  const zone = new StaticResolver({
    'MX example.com': ['1 aspmx.l.google.com', '5 alt1.aspmx.l.google.com'],
    'A aspmx.l.google.com': ['142.250.1.26'],
    'A alt1.aspmx.l.google.com': ['142.250.1.27'],
    'TXT _mta-sts.example.com': ['v=STSv1; id=20261108'],
    'TXT _smtp._tls.example.com': ['v=TLSRPTv1; rua=mailto:tls@example.com'],
    'MX nullmx.com': ['0 .'],
    'TXT default._bimi.example.com': ['v=BIMI1; l=https://example.com/logo.svg; a='],
    'TXT _dmarc.example.com': ['v=DMARC1; p=reject'],
  });

  it('analyzes MX and detects provider', async () => {
    const r = await analyzeMx('example.com', zone);
    expect(r.status).toBe('ok');
    expect(r.provider).toBe('Google Workspace');
    expect(r.hosts[0]!.addresses).toEqual(['142.250.1.26']);
    expect((await analyzeMx('nullmx.com', zone)).status).toBe('null-mx');
  });

  it('validates MTA-STS policy against MX hosts', async () => {
    const policy = buildMtaStsPolicy('enforce', ['*.aspmx.l.google.com'], 604800);
    const r = await analyzeMtaSts('example.com', zone, async () => ({ ok: true, body: policy }), ['aspmx.l.google.com', 'alt1.aspmx.l.google.com']);
    // "*.aspmx.l.google.com" matches alt1.aspmx.l.google.com but not aspmx.l.google.com itself
    expect(r.unmatchedMx).toEqual(['aspmx.l.google.com']);
    expect(r.status).toBe('invalid');
    expect(mxMatchesPattern('alt1.aspmx.l.google.com', '*.aspmx.l.google.com')).toBe(true);
    expect(mxMatchesPattern('a.b.aspmx.l.google.com', '*.aspmx.l.google.com')).toBe(false);
    const ok = await analyzeMtaSts('example.com', zone, async () => ({ ok: true, body: buildMtaStsPolicy('testing', ['aspmx.l.google.com', '*.aspmx.l.google.com'], 86400) }), ['aspmx.l.google.com']);
    expect(ok.status).toBe('ok');
    expect(ok.policy?.mode).toBe('testing');
  });

  it('parses policies', () => {
    expect(parseMtaStsPolicy('version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n').valid).toBe(true);
    expect(parseMtaStsPolicy('version: STSv1\nmode: strict\nmax_age: 1').valid).toBe(false);
  });

  it('checks TLS-RPT and BIMI', async () => {
    expect((await analyzeTlsRpt('example.com', zone)).rua).toEqual(['mailto:tls@example.com']);
    const dmarc = await analyzeDmarc('example.com', zone);
    const bimi = await analyzeBimi('example.com', zone, dmarc);
    expect(bimi.status).toBe('ok');
    expect(bimi.warnings.join(' ')).toMatch(/VMC/);
  });
});

describe('blacklists', () => {
  it('handles listed, clean and refused answers', async () => {
    const zone = new StaticResolver({
      'A 2.0.0.127.zen.spamhaus.org': ['127.0.0.2'],
      'A 2.0.0.127.bl.spamcop.net': ['127.0.0.2'],
      'A 5.113.0.203.zen.spamhaus.org': ['127.255.255.254'],
      'A anything.example': ['1.1.1.1'],
    });
    const listed = await checkIpBlocklists('127.0.0.2', zone);
    expect(listed.filter((r) => r.status === 'listed').map((r) => r.zone).sort()).toEqual(['bl.spamcop.net', 'zen.spamhaus.org']);
    const refused = await checkIpBlocklists('203.0.113.5', zone);
    expect(refused.find((r) => r.zone === 'zen.spamhaus.org')!.status).toBe('unknown');
    const a = await analyzeBlacklists('example.com', ['127.0.0.2', '127.0.0.2', '2001:db8::1'], zone);
    expect(a.checkedIps).toEqual(['127.0.0.2']);
    expect(a.listed).toHaveLength(2);
  });
});

describe('senders', () => {
  it('identifies by auth domain, PTR and ASN', () => {
    expect(identifySender({ authDomains: ['bounces.sendgrid.net'] })?.key).toBe('sendgrid');
    expect(identifySender({ ptr: 'mail-sor-f41.google.com' })?.key).toBe('google');
    expect(identifySender({ asn: 8075 })?.key).toBe('microsoft');
    expect(identifySender({ ptr: 'host.unknown.example' })).toBeUndefined();
  });

  it('looks up PTR and ASN via DNS', async () => {
    const zone = new StaticResolver({
      'PTR 41.220.85.209.in-addr.arpa': ['mail-sor-f41.google.com'],
      'TXT 41.220.85.209.origin.asn.cymru.com': ['15169 | 209.85.128.0/17 | US | arin | 2002-12-11'],
      'TXT AS15169.asn.cymru.com': ['15169 | US | arin | 2000-03-30 | GOOGLE, US'],
    });
    const intel = await lookupIpIntel('209.85.220.41', zone);
    expect(intel).toEqual({ ip: '209.85.220.41', ptr: 'mail-sor-f41.google.com', asn: 15169, asName: 'GOOGLE, US', country: 'US' });
  });
});

describe('aggregate reports', () => {
  it('parses an RFC 7489 report', () => {
    const r = parseAggregateReport(GOOGLE_REPORT_XML);
    expect(r.orgName).toBe('google.com');
    expect(r.reportId).toBe('4865322011347193701');
    expect(r.policy).toMatchObject({ domain: 'example.com', p: 'none', pct: 100 });
    expect(r.records).toHaveLength(3);
    expect(r.records[0]).toMatchObject({ sourceIp: '209.85.220.41', count: 120, dkimAligned: true, spfAligned: true });
    expect(r.records[1]!.reasons).toEqual([{ type: 'forwarded', comment: 'looks forwarded' }]);
    expect(r.records[2]!.dkim).toHaveLength(2);
    const s = summarizeRecords(r.records);
    expect(s).toMatchObject({ total: 167, passing: 160, dkimAligned: 160, spfAligned: 120 });
    expect(s.passRate).toBeCloseTo(160 / 167);
  });

  it('parses an RFC 9990 namespaced report', () => {
    const r = parseAggregateReport(RFC9990_REPORT_XML);
    expect(r.policy).toMatchObject({ domain: 'example.org', p: 'reject', np: 'reject', testing: 'n', discoveryMethod: 'treewalk' });
    expect(r.errors).toEqual(['one record skipped']);
    expect(r.records[0]).toMatchObject({ sourceIp: '2001:db8::25', disposition: 'reject', envelopeFrom: 'bounce.example.org' });
    expect(r.records[0]!.spf[0]).toEqual({ domain: 'bounce.example.org', scope: 'mfrom', result: 'fail' });
  });

  it('unpacks gzip and zip attachments', () => {
    const gz = gzipSync(strToU8(GOOGLE_REPORT_XML));
    expect(parseAggregateReport(unpackReport(gz)[0]!).reportId).toBe('4865322011347193701');
    const zip = zipSync({ 'google.com!example.com!1!2.xml': strToU8(GOOGLE_REPORT_XML), 'readme.txt': strToU8('x') });
    expect(unpackReport(zip)).toHaveLength(1);
    expect(unpackReport(strToU8(RFC9990_REPORT_XML))[0]).toContain('feedback');
  });

  it('rejects non-reports', () => {
    expect(() => parseAggregateReport('<html></html>')).toThrow(ReportParseError);
    expect(() => parseAggregateReport('<feedback><report_metadata/></feedback>')).toThrow(/missing/);
  });
});

describe('generators and enforcement', () => {
  it('builds SPF records', () => {
    const r = buildSpf({ includes: ['_spf.google.com', 'sendgrid.net', '_spf.google.com'], ip4: ['192.0.2.0/24'], all: '-' });
    expect(r.record).toBe('v=spf1 ip4:192.0.2.0/24 include:_spf.google.com include:sendgrid.net -all');
    expect(r.directLookups).toBe(2);
    expect(buildSpf({ ip4: ['999.1.1.1'], all: '~' }).errors).toHaveLength(1);
  });

  it('gates the ladder on readiness', () => {
    expect(stepIndex('none', false)).toBe(0);
    expect(stepIndex('reject', true)).toBe(3);
    const good = readiness({ daysWithData: 14, passRate: 0.995, largestUnknownShare: 0.001, spfLookups: 6, hasDkim: true });
    expect(good.ready).toBe(true);
    expect(nextStep(0, good.ready)).toEqual(ENFORCEMENT_LADDER[1]);
    const bad = readiness({ daysWithData: 3, passRate: 0.9, largestUnknownShare: 0.2, spfLookups: 12, hasDkim: false });
    expect(bad.checks.filter((c) => !c.ok)).toHaveLength(5);
    expect(nextStep(0, bad.ready)).toBeNull();
    expect(nextStep(4, true)).toBeNull();
  });
});
