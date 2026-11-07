import { describe, expect, it } from 'vitest';
import { customerRecords, flattenForHosting, renderZoneRecords, verificationRecord, type HostedEnv } from '../src/hosted.ts';
import { parseDmarc } from '../src/dmarc.ts';

const env: HostedEnv = { zone: 'dns.mailyflex.com', ruaDomain: 'rua.mailyflex.com', tlsRptDomain: 'tls.mailyflex.com', mtaStsTarget: 'sts.dns.mailyflex.com' };

describe('hosted records', () => {
  it('renders zone records for every enabled feature', () => {
    const spf = flattenForHosting('tok1', ['192.0.2.0/24', '192.0.2.5'], ['2001:db8::/32'], [], env);
    const recs = renderZoneRecords(
      {
        name: 'acme.com',
        token: 'tok1',
        dmarc: { p: 'quarantine', np: 'reject', t: true, extraRua: ['mailto:sec@acme.com'] },
        spfFlattened: spf,
        mtaSts: { mode: 'enforce', policyId: '20261108', tlsrptEnabled: true },
      },
      env,
    );
    expect(recs).toEqual([
      { name: 'tok1._d.dns.mailyflex.com', type: 'TXT', content: 'v=DMARC1; p=quarantine; np=reject; t=y; rua=mailto:tok1@rua.mailyflex.com,mailto:sec@acme.com' },
      { name: 'tok1._s.dns.mailyflex.com', type: 'TXT', content: 'v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32' },
      { name: 'tok1._m.dns.mailyflex.com', type: 'TXT', content: 'v=STSv1; id=20261108' },
      { name: 'tok1._t.dns.mailyflex.com', type: 'TXT', content: 'v=TLSRPTv1; rua=mailto:tok1@tls.mailyflex.com' },
    ]);
    expect(parseDmarc(recs[0]!.content).valid).toBe(true);
  });

  it('renders nothing for a domain with no hosted features', () => {
    expect(renderZoneRecords({ name: 'x.com', token: 't' }, env)).toEqual([]);
  });

  it('gives customers delegation records', () => {
    const c = customerRecords('acme.com', 'tok1', env, { allQualifier: '-' });
    expect(c.dmarc[0]).toMatchObject({ type: 'CNAME', host: '_dmarc.acme.com', value: 'tok1._d.dns.mailyflex.com' });
    expect(c.spf[0]!.value).toBe('v=spf1 include:tok1._s.dns.mailyflex.com -all');
    expect(c.mtaSts.map((r) => r.host)).toEqual(['_mta-sts.acme.com', 'mta-sts.acme.com', '_smtp._tls.acme.com']);
    expect(verificationRecord('acme.com', 'v1')).toMatchObject({ host: '_mailyflex.acme.com', value: 'mailyflex-verify=v1' });
  });
});
