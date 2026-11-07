import { describe, expect, it } from 'vitest';
import { StaticResolver, DohResolver } from '../src/dns.ts';
import { diffSnapshots, scanDomain } from '../src/health.ts';
import { rsaSpki } from './fixtures.ts';

describe('scanDomain', () => {
  it('scores a well-configured domain highly', async () => {
    const key = await rsaSpki(2048);
    const zone = new StaticResolver({
      'TXT good.com': ['v=spf1 include:_spf.google.com -all'],
      'TXT _spf.google.com': ['v=spf1 ip4:35.190.247.0/24 ~all'],
      'TXT _dmarc.good.com': ['v=DMARC1; p=reject; rua=mailto:r@good.com'],
      'TXT google._domainkey.good.com': [`v=DKIM1; k=rsa; p=${key}`],
      'MX good.com': ['1 smtp.google.com'],
      'A smtp.google.com': ['142.250.1.26'],
      'TXT _mta-sts.good.com': ['v=STSv1; id=1'],
      'TXT _smtp._tls.good.com': ['v=TLSRPTv1; rua=mailto:t@good.com'],
      'TXT default._bimi.good.com': ['v=BIMI1; l=https://good.com/l.svg; a=https://good.com/vmc.pem'],
    });
    const policy = 'version: STSv1\nmode: enforce\nmx: smtp.google.com\nmax_age: 604800\n';
    const r = await scanDomain('Good.com', { resolver: zone, policyFetcher: async () => ({ ok: true, body: policy }) });
    expect(r.domain).toBe('good.com');
    expect(r.score).toBe(100);
    expect(r.grade).toBe('A');
    expect(r.fixes.filter((f) => f.severity !== 'info')).toEqual([]);
    expect(r.records.dmarc).toEqual(['v=DMARC1; p=reject; rua=mailto:r@good.com']);
    expect(r.records['dkim:google']).toHaveLength(1);
  });

  it('gives a bare domain a failing score with critical fixes and copy-paste records', async () => {
    const zone = new StaticResolver({
      'MX bare.com': ['10 bare-com.mail.protection.outlook.com'],
      'A bare-com.mail.protection.outlook.com': ['52.101.1.1'],
      'TXT bare.com': ['MS=ms123'],
    });
    const r = await scanDomain('bare.com', { resolver: zone, ruaAddress: 'tok@rua.mailyflex.com' });
    expect(r.score).toBeLessThan(20);
    expect(r.grade).toBe('F');
    const ids = r.fixes.map((f) => f.id);
    expect(ids.slice(0, 3).sort()).toEqual(['dkim-missing', 'dmarc-missing', 'spf-missing']);
    expect(r.fixes.find((f) => f.id === 'spf-missing')!.record!.value).toBe('v=spf1 include:spf.protection.outlook.com -all');
    expect(r.fixes.find((f) => f.id === 'dmarc-missing')!.record).toEqual({ type: 'TXT', host: '_dmarc.bare.com', value: 'v=DMARC1; p=none; rua=mailto:tok@rua.mailyflex.com' });
  });

  it('penalises blacklist listings', async () => {
    const zone = new StaticResolver({
      'TXT bl.com': ['v=spf1 -all'],
      'TXT _dmarc.bl.com': ['v=DMARC1; p=reject; rua=mailto:r@bl.com'],
      'A bl.com.dbl.spamhaus.org': ['127.0.1.2'],
      'MX bl.com': ['0 .'],
    });
    const withBl = await scanDomain('bl.com', { resolver: zone });
    const noBl = await scanDomain('bl.com', { resolver: zone, blacklists: false });
    expect(noBl.score - withBl.score).toBe(10);
    expect(withBl.fixes.find((f) => f.area === 'blacklist')?.severity).toBe('critical');
  });

  it('diffs record snapshots', () => {
    const changes = diffSnapshots({ spf: ['v=spf1 -all'], dmarc: ['a'] }, { spf: ['v=spf1 ~all'], dmarc: ['a'], 'dkim:s1': ['k'] });
    expect(changes.map((c) => c.key)).toEqual(['dkim:s1', 'spf']);
  });
});

describe.skipIf(!process.env.LIVE_DNS)('live DNS (LIVE_DNS=1)', () => {
  it('scans real domains over DoH', async () => {
    const resolver = new DohResolver();
    for (const d of ['google.com', 'github.com']) {
      const r = await scanDomain(d, { resolver, blacklists: false });
      console.log(d, r.score, r.grade, `spf=${r.spf.status}/${r.spf.lookupCount}`, `dmarc=${r.dmarc.policy}`, `dkim=${r.dkim.selectors.map((s) => s.selector).join(',')}`, `mx=${r.mx.provider}`);
      expect(r.dmarc.status).toBe('ok');
      expect(r.spf.status).toBe('ok');
      expect(r.mx.hosts.length).toBeGreaterThan(0);
    }
  }, 60000);
});
