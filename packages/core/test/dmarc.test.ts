import { describe, expect, it } from 'vitest';
import { StaticResolver } from '../src/dns.ts';
import { analyzeDmarc, buildDmarc, orgDomain, parseDmarc } from '../src/dmarc.ts';

describe('parseDmarc (RFC 9989)', () => {
  it('parses new tags np, psd, t', () => {
    const p = parseDmarc('v=DMARC1; p=reject; sp=quarantine; np=reject; psd=n; t=y; adkim=s; rua=mailto:a@example.com,mailto:b@x.net');
    expect(p.valid).toBe(true);
    expect(p.record).toMatchObject({ p: 'reject', sp: 'quarantine', np: 'reject', psd: 'n', t: 'y', adkim: 's', aspf: 'r' });
    expect(p.record.rua).toEqual(['mailto:a@example.com', 'mailto:b@x.net']);
  });

  it('flags historic tags', () => {
    const p = parseDmarc('v=DMARC1; p=none; pct=50; rf=afrf; ri=3600');
    expect(p.valid).toBe(true);
    expect(p.warnings.filter((w) => /historic/.test(w))).toHaveLength(3);
  });

  it('rejects invalid values', () => {
    expect(parseDmarc('p=reject; v=DMARC1').errors[0]).toMatch(/start with/);
    expect(parseDmarc('v=DMARC1; p=block').valid).toBe(false);
    expect(parseDmarc('v=DMARC1; p=none; t=maybe').valid).toBe(false);
    expect(parseDmarc('v=DMARC1; p=none; rua=a@b.com').errors[0]).toMatch(/mailto/);
    expect(parseDmarc('v=DMARC1').errors[0]).toMatch(/Missing required "p"/);
  });

  it('treats missing p with rua as none', () => {
    const p = parseDmarc('v=DMARC1; rua=mailto:x@example.com');
    expect(p.valid).toBe(true);
  });

  it('strips RFC 7489 size suffix', () => {
    expect(parseDmarc('v=DMARC1; p=none; rua=mailto:a@example.com!10m').record.rua).toEqual(['mailto:a@example.com']);
  });
});

const zone = new StaticResolver({
  'TXT _dmarc.example.com': ['v=DMARC1; p=quarantine; t=y; rua=mailto:abc@rua.mailyflex.com'],
  'TXT example.com._report._dmarc.rua.mailyflex.com': ['v=DMARC1'],
  'TXT _dmarc.parent.co.uk': ['v=DMARC1; p=reject; sp=none; rua=mailto:d@parent.co.uk'],
  'TXT _dmarc.unauth.com': ['v=DMARC1; p=reject; rua=mailto:r@other-vendor.net'],
  'TXT _dmarc.dup.com': ['v=DMARC1; p=none', 'v=DMARC1; p=reject'],
  'TXT a.b.c.d.e.f.g.h.i.deep.com': [],
  'TXT _dmarc.deep.com': ['v=DMARC1; p=reject'],
});

describe('analyzeDmarc', () => {
  it('applies t=y to compute the effective policy and checks external rua', async () => {
    const r = await analyzeDmarc('example.com', zone);
    expect(r.status).toBe('ok');
    expect(r.policy).toBe('quarantine');
    expect(r.effectivePolicy).toBe('none');
    expect(r.ruaChecks[0]).toMatchObject({ external: true, authorized: true });
  });

  it('tree-walks to the parent and uses sp', async () => {
    const r = await analyzeDmarc('mail.parent.co.uk', zone);
    expect(r.inherited).toBe(true);
    expect(r.foundAt).toBe('parent.co.uk');
    expect(r.policy).toBe('none');
  });

  it('caps the tree walk for deep names but still finds the org record', async () => {
    const r = await analyzeDmarc('a.b.c.d.e.f.g.h.i.deep.com', zone);
    expect(r.foundAt).toBe('deep.com');
  });

  it('flags unauthorised external report addresses', async () => {
    const r = await analyzeDmarc('unauth.com', zone);
    expect(r.status).toBe('invalid');
    expect(r.errors.join(' ')).toMatch(/dropped/);
  });

  it('flags duplicates and missing', async () => {
    expect((await analyzeDmarc('dup.com', zone)).status).toBe('multiple');
    expect((await analyzeDmarc('nothing.com', zone)).status).toBe('missing');
  });
});

describe('helpers', () => {
  it('org domain', () => {
    expect(orgDomain('mail.example.co.uk')).toBe('example.co.uk');
    expect(orgDomain('a.b.example.com')).toBe('example.com');
  });

  it('builds records without historic tags by default', () => {
    expect(buildDmarc({ p: 'reject', np: 'reject', rua: ['r@x.com'] })).toBe('v=DMARC1; p=reject; np=reject; rua=mailto:r@x.com');
    expect(buildDmarc({ p: 'quarantine', t: true, legacyPct: 25 })).toBe('v=DMARC1; p=quarantine; t=y; pct=25');
    const roundTrip = parseDmarc(buildDmarc({ p: 'reject', sp: 'quarantine', adkim: 's', aspf: 's', rua: ['a@b.com'], ruf: ['c@b.com'], fo: '1' }));
    expect(roundTrip.valid).toBe(true);
    expect(roundTrip.warnings).toEqual([]);
  });
});
