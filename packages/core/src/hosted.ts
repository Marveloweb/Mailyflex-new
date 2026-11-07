/**
 * Hosted (managed) DNS: the records Maily Flex publishes in its own zone, and the one-time
 * records a customer adds to delegate to them. Names are keyed on the domain's random report
 * token so they never collide between customers and never exceed DNS length limits.
 */
import { buildDmarc, type Alignment, type DmarcPolicy } from './dmarc.ts';
import { flattenSpf, type FlatRecord } from './spf.ts';

export interface HostedEnv {
  /** Zone Maily Flex controls, e.g. "dns.mailyflex.com". */
  zone: string;
  /** Domain that receives DMARC aggregate reports, e.g. "rua.mailyflex.com". */
  ruaDomain: string;
  /** Domain that receives TLS-RPT reports, e.g. "tls.mailyflex.com". */
  tlsRptDomain: string;
  /** CNAME target for mta-sts.<customer> (Cloudflare for SaaS fallback origin), e.g. "sts.dns.mailyflex.com". */
  mtaStsTarget: string;
}

export interface HostedDmarcConfig {
  p: DmarcPolicy;
  sp?: DmarcPolicy | null;
  np?: DmarcPolicy | null;
  adkim?: Alignment;
  aspf?: Alignment;
  t?: boolean;
  extraRua?: string[];
}

export interface HostedMtaStsConfig {
  mode: 'none' | 'testing' | 'enforce';
  policyId: string;
  tlsrptEnabled: boolean;
}

export interface HostedDomainState {
  name: string;
  token: string;
  dmarc?: HostedDmarcConfig | null;
  spfFlattened?: FlatRecord[] | null;
  mtaSts?: HostedMtaStsConfig | null;
}

export interface ZoneRecord {
  name: string;
  type: 'TXT';
  content: string;
}

export function hostedNames(token: string, env: HostedEnv) {
  return {
    dmarc: `${token}._d.${env.zone}`,
    spf: `${token}._s.${env.zone}`,
    mtaSts: `${token}._m.${env.zone}`,
    tlsRpt: `${token}._t.${env.zone}`,
  };
}

export function reportAddress(token: string, env: HostedEnv): string {
  return `${token}@${env.ruaDomain}`;
}

export function hostedDmarcValue(cfg: HostedDmarcConfig, token: string, env: HostedEnv): string {
  return buildDmarc({
    p: cfg.p,
    ...(cfg.sp ? { sp: cfg.sp } : {}),
    ...(cfg.np ? { np: cfg.np } : {}),
    adkim: cfg.adkim ?? 'r',
    aspf: cfg.aspf ?? 'r',
    t: !!cfg.t,
    rua: [reportAddress(token, env), ...(cfg.extraRua ?? [])],
  });
}

/** All TXT records Maily Flex should publish in its zone for one domain. */
export function renderZoneRecords(d: HostedDomainState, env: HostedEnv): ZoneRecord[] {
  const n = hostedNames(d.token, env);
  const out: ZoneRecord[] = [];
  if (d.dmarc) out.push({ name: n.dmarc, type: 'TXT', content: hostedDmarcValue(d.dmarc, d.token, env) });
  for (const r of d.spfFlattened ?? []) out.push({ name: r.host, type: 'TXT', content: r.value });
  if (d.mtaSts) {
    out.push({ name: n.mtaSts, type: 'TXT', content: `v=STSv1; id=${d.mtaSts.policyId}` });
    if (d.mtaSts.tlsrptEnabled) out.push({ name: n.tlsRpt, type: 'TXT', content: `v=TLSRPTv1; rua=mailto:${d.token}@${env.tlsRptDomain}` });
  }
  return out;
}

export function flattenForHosting(token: string, ip4: string[], ip6: string[], keep: string[], env: HostedEnv): FlatRecord[] {
  return flattenSpf(ip4, ip6, { baseHost: hostedNames(token, env).spf, keep });
}

export interface CustomerRecord {
  feature: 'verify' | 'dmarc' | 'spf' | 'mta-sts' | 'tls-rpt';
  type: 'TXT' | 'CNAME';
  host: string;
  value: string;
  note?: string;
}

export function verificationRecord(domain: string, verificationToken: string): CustomerRecord {
  return { feature: 'verify', type: 'TXT', host: `_mailyflex.${domain}`, value: `mailyflex-verify=${verificationToken}` };
}

/** Records the customer adds once at their DNS provider to delegate a feature to Maily Flex. */
export function customerRecords(domain: string, token: string, env: HostedEnv, opts: { allQualifier?: '-' | '~' } = {}): Record<'dmarc' | 'spf' | 'mtaSts', CustomerRecord[]> {
  const n = hostedNames(token, env);
  return {
    dmarc: [{ feature: 'dmarc', type: 'CNAME', host: `_dmarc.${domain}`, value: n.dmarc, note: 'Delete any existing TXT record at _dmarc first.' }],
    spf: [
      {
        feature: 'spf',
        type: 'TXT',
        host: domain,
        value: `v=spf1 include:${n.spf} ${opts.allQualifier ?? '~'}all`,
        note: 'Replace your existing v=spf1 record (keep other TXT records such as site verifications).',
      },
    ],
    mtaSts: [
      { feature: 'mta-sts', type: 'CNAME', host: `_mta-sts.${domain}`, value: n.mtaSts },
      { feature: 'mta-sts', type: 'CNAME', host: `mta-sts.${domain}`, value: env.mtaStsTarget, note: 'If your DNS is on Cloudflare, set this record to "DNS only" (grey cloud).' },
      { feature: 'tls-rpt', type: 'CNAME', host: `_smtp._tls.${domain}`, value: n.tlsRpt },
    ],
  };
}
