/**
 * MX, MTA-STS (RFC 8461), TLS-RPT (RFC 8460) and BIMI checks.
 */
import { resolveTxt, type Resolver } from './dns.ts';
import type { DmarcAnalysis } from './dmarc.ts';

// ---------- MX ----------

export interface MxHost {
  priority: number;
  host: string;
  addresses: string[];
  provider?: string;
}

export interface MxAnalysis {
  domain: string;
  status: 'ok' | 'missing' | 'null-mx' | 'invalid' | 'error';
  hosts: MxHost[];
  provider?: string;
  errors: string[];
  warnings: string[];
}

const MX_PROVIDERS: [RegExp, string][] = [
  [/(^|\.)(google\.com|googlemail\.com|smtp\.google\.com)$/, 'Google Workspace'],
  [/\.mail\.protection\.outlook\.com$|\.mx\.microsoft$/, 'Microsoft 365'],
  [/(^|\.)zoho\.(com|eu|in|com\.au|jp)$/, 'Zoho Mail'],
  [/(^|\.)protonmail\.ch$/, 'Proton Mail'],
  [/(^|\.)messagingengine\.com$/, 'Fastmail'],
  [/(^|\.)mail\.icloud\.com$/, 'iCloud Mail'],
  [/(^|\.)pphosted\.com$|ppe-hosted\.com$/, 'Proofpoint'],
  [/(^|\.)mimecast\.com$/, 'Mimecast'],
  [/(^|\.)barracudanetworks\.com$/, 'Barracuda'],
  [/(^|\.)secureserver\.net$/, 'GoDaddy'],
  [/(^|\.)yandex\.(net|ru)$/, 'Yandex'],
  [/(^|\.)titan\.email$/, 'Titan'],
  [/(^|\.)hostinger\.com$/, 'Hostinger'],
  [/(^|\.)amazonaws\.com$/, 'Amazon SES / WorkMail'],
  [/(^|\.)mxrouting\.net$/, 'MXroute'],
  [/(^|\.)improvmx\.com$/, 'ImprovMX'],
  [/(^|\.)forwardemail\.net$/, 'Forward Email'],
  [/(^|\.)mx\.cloudflare\.net$/, 'Cloudflare Email Routing'],
];

export function mxProvider(host: string): string | undefined {
  return MX_PROVIDERS.find(([re]) => re.test(host.toLowerCase()))?.[1];
}

export async function analyzeMx(domain: string, resolver: Resolver): Promise<MxAnalysis> {
  const r = await resolver.query(domain, 'MX');
  const errors: string[] = [];
  const warnings: string[] = [];
  if (r.status === 'ERROR' || r.status === 'SERVFAIL') return { domain, status: 'error', hosts: [], errors: [`DNS lookup failed: ${r.error ?? r.status}`], warnings };
  if (r.status === 'NXDOMAIN') return { domain, status: 'missing', hosts: [], errors: ['Domain does not exist (NXDOMAIN).'], warnings };
  const recs = r.answers
    .map((a) => {
      const [prio, host] = a.data.split(/\s+/);
      return { priority: Number(prio), host: (host ?? '').replace(/\.$/, '') };
    })
    .sort((a, b) => a.priority - b.priority);
  if (recs.length === 0) {
    return { domain, status: 'missing', hosts: [], errors: [], warnings: ['No MX record: this domain cannot receive email (mail falls back to the A record).'] };
  }
  if (recs.length === 1 && (recs[0]!.host === '' || recs[0]!.host === '.')) {
    return { domain, status: 'null-mx', hosts: [], errors: [], warnings: ['Null MX (RFC 7505): this domain explicitly accepts no email.'] };
  }
  const hosts: MxHost[] = await Promise.all(
    recs.map(async (m) => {
      const [a, aaaa] = await Promise.all([resolver.query(m.host, 'A'), resolver.query(m.host, 'AAAA')]);
      const addresses = [...a.answers, ...aaaa.answers].map((x) => x.data);
      const provider = mxProvider(m.host);
      return { ...m, addresses, ...(provider ? { provider } : {}) };
    }),
  );
  for (const h of hosts) {
    if (h.addresses.length === 0) errors.push(`MX host ${h.host} does not resolve to an IP address.`);
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h.host)) errors.push(`MX ${h.host} is an IP address; MX records must point to hostnames.`);
  }
  const provider = hosts.find((h) => h.provider)?.provider;
  return { domain, status: errors.length ? 'invalid' : 'ok', hosts, ...(provider ? { provider } : {}), errors, warnings };
}

// ---------- MTA-STS ----------

export interface MtaStsPolicy {
  version?: string;
  mode?: 'enforce' | 'testing' | 'none';
  mx: string[];
  maxAge?: number;
}

export function parseMtaStsTxt(txt: string): { valid: boolean; id?: string; errors: string[] } {
  const errors: string[] = [];
  const tags: Record<string, string> = {};
  for (const part of txt.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
  }
  if (tags.v !== 'STSv1') errors.push('Record must start with v=STSv1.');
  if (!tags.id) errors.push('Missing id= (change it every time the policy changes).');
  else if (!/^[A-Za-z0-9]{1,32}$/.test(tags.id)) errors.push('id must be 1–32 letters or digits.');
  return { valid: errors.length === 0, ...(tags.id ? { id: tags.id } : {}), errors };
}

export function parseMtaStsPolicy(text: string): { valid: boolean; policy: MtaStsPolicy; errors: string[]; warnings: string[] } {
  const errors: string[] = [];
  const warnings: string[] = [];
  const policy: MtaStsPolicy = { mx: [] };
  for (const line of text.split(/\r?\n/)) {
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (key === 'version') policy.version = value;
    else if (key === 'mode') {
      if (value === 'enforce' || value === 'testing' || value === 'none') policy.mode = value;
      else errors.push(`mode "${value}" is invalid; use enforce, testing or none.`);
    } else if (key === 'mx') policy.mx.push(value.toLowerCase());
    else if (key === 'max_age') {
      const n = Number(value);
      if (!/^\d{1,10}$/.test(value) || n > 31557600) errors.push('max_age must be 0–31557600 seconds.');
      else policy.maxAge = n;
    }
  }
  if (policy.version !== 'STSv1') errors.push('Policy must contain "version: STSv1".');
  if (!policy.mode) errors.push('Policy is missing "mode".');
  if (policy.maxAge === undefined) errors.push('Policy is missing "max_age".');
  else if (policy.maxAge < 86400) warnings.push('max_age under 1 day: senders re-fetch the policy constantly. Use at least 604800 (1 week) in enforce mode.');
  if (policy.mode !== 'none' && policy.mx.length === 0) errors.push('Policy lists no "mx" hosts.');
  if (policy.mode === 'testing') warnings.push('Mode is "testing": TLS failures are reported but mail is still delivered.');
  return { valid: errors.length === 0, policy, errors, warnings };
}

export function mxMatchesPattern(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const p = pattern.toLowerCase().replace(/\.$/, '');
  if (p.startsWith('*.')) {
    const suffix = p.slice(1);
    return h.endsWith(suffix) && !h.slice(0, -suffix.length).includes('.');
  }
  return h === p;
}

export type PolicyFetcher = (domain: string) => Promise<{ ok: boolean; status?: number; body?: string; error?: string }>;

/** Default fetcher (server-side only; browsers block it with CORS). */
export const directPolicyFetcher: PolicyFetcher = async (domain) => {
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 5000);
    try {
      const res = await fetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, { redirect: 'manual', signal: ctrl.signal });
      if (res.status !== 200) return { ok: false, status: res.status, error: `HTTP ${res.status} (redirects are not allowed)` };
      const body = (await res.text()).slice(0, 65536);
      return { ok: true, status: 200, body };
    } finally {
      clearTimeout(timer);
    }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
};

export interface MtaStsAnalysis {
  domain: string;
  status: 'ok' | 'missing' | 'invalid' | 'error';
  txt?: string;
  id?: string;
  policyText?: string;
  policy?: MtaStsPolicy;
  unmatchedMx: string[];
  errors: string[];
  warnings: string[];
}

export async function analyzeMtaSts(domain: string, resolver: Resolver, fetcher: PolicyFetcher | null, mxHosts?: string[]): Promise<MtaStsAnalysis> {
  const errors: string[] = [];
  const warnings: string[] = [];
  const r = await resolveTxt(resolver, `_mta-sts.${domain}`);
  if (r.status === 'ERROR' || r.status === 'SERVFAIL') return { domain, status: 'error', unmatchedMx: [], errors: ['DNS lookup failed.'], warnings };
  const recs = r.records.filter((t) => /^v=STSv1/i.test(t));
  if (recs.length === 0) {
    return { domain, status: 'missing', unmatchedMx: [], errors: [], warnings: ['No MTA-STS record: senders may deliver mail to you over unencrypted or downgraded connections.'] };
  }
  if (recs.length > 1) errors.push('More than one MTA-STS TXT record; senders will ignore the policy.');
  const txt = recs[0]!;
  const parsedTxt = parseMtaStsTxt(txt);
  errors.push(...parsedTxt.errors);
  const out: MtaStsAnalysis = { domain, status: 'ok', txt, ...(parsedTxt.id ? { id: parsedTxt.id } : {}), unmatchedMx: [], errors, warnings };
  if (!fetcher) return { ...out, status: errors.length ? 'invalid' : 'ok' };
  const fetched = await fetcher(domain);
  if (!fetched.ok || fetched.body === undefined) {
    errors.push(`Could not fetch https://mta-sts.${domain}/.well-known/mta-sts.txt (${fetched.error ?? `HTTP ${fetched.status}`}).`);
    return { ...out, status: 'invalid' };
  }
  const parsed = parseMtaStsPolicy(fetched.body);
  out.policyText = fetched.body;
  out.policy = parsed.policy;
  errors.push(...parsed.errors);
  warnings.push(...parsed.warnings);
  if (mxHosts && parsed.policy.mode !== 'none') {
    out.unmatchedMx = mxHosts.filter((h) => !parsed.policy.mx.some((p) => mxMatchesPattern(h, p)));
    for (const h of out.unmatchedMx) {
      const msg = `MX host ${h} is not listed in the policy; in enforce mode, senders will refuse to deliver to it.`;
      if (parsed.policy.mode === 'enforce') errors.push(msg);
      else warnings.push(msg);
    }
  }
  out.status = errors.length ? 'invalid' : 'ok';
  return out;
}

export function buildMtaStsPolicy(mode: 'enforce' | 'testing' | 'none', mx: string[], maxAge = 604800): string {
  return ['version: STSv1', `mode: ${mode}`, ...mx.map((m) => `mx: ${m}`), `max_age: ${maxAge}`].join('\r\n') + '\r\n';
}

// ---------- TLS-RPT ----------

export interface TlsRptAnalysis {
  domain: string;
  status: 'ok' | 'missing' | 'invalid' | 'error';
  record?: string;
  rua: string[];
  errors: string[];
  warnings: string[];
}

export async function analyzeTlsRpt(domain: string, resolver: Resolver): Promise<TlsRptAnalysis> {
  const r = await resolveTxt(resolver, `_smtp._tls.${domain}`);
  if (r.status === 'ERROR' || r.status === 'SERVFAIL') return { domain, status: 'error', rua: [], errors: ['DNS lookup failed.'], warnings: [] };
  const recs = r.records.filter((t) => /^v=TLSRPTv1/i.test(t));
  if (recs.length === 0) {
    return { domain, status: 'missing', rua: [], errors: [], warnings: ['No TLS-RPT record: you will not hear about TLS delivery failures to your domain.'] };
  }
  const errors: string[] = [];
  if (recs.length > 1) errors.push('More than one TLS-RPT record.');
  const record = recs[0]!;
  const m = /rua\s*=\s*([^;]+)/i.exec(record);
  const rua = m ? m[1]!.split(',').map((s) => s.trim()).filter(Boolean) : [];
  if (rua.length === 0) errors.push('TLS-RPT record has no rua= destination.');
  for (const u of rua) if (!/^mailto:[^@\s]+@[^@\s]+$/i.test(u) && !/^https:\/\//i.test(u)) errors.push(`"${u}" is not a mailto: or https: URI.`);
  return { domain, status: errors.length ? 'invalid' : 'ok', record, rua, errors, warnings: [] };
}

// ---------- BIMI ----------

export interface BimiAnalysis {
  domain: string;
  status: 'ok' | 'missing' | 'invalid' | 'error';
  record?: string;
  logoUrl?: string;
  authorityUrl?: string;
  errors: string[];
  warnings: string[];
}

export async function analyzeBimi(domain: string, resolver: Resolver, dmarc?: DmarcAnalysis, selector = 'default'): Promise<BimiAnalysis> {
  const r = await resolveTxt(resolver, `${selector}._bimi.${domain}`);
  if (r.status === 'ERROR' || r.status === 'SERVFAIL') return { domain, status: 'error', errors: ['DNS lookup failed.'], warnings: [] };
  const recs = r.records.filter((t) => /^v=BIMI1/i.test(t));
  if (recs.length === 0) return { domain, status: 'missing', errors: [], warnings: [] };
  const errors: string[] = [];
  const warnings: string[] = [];
  const record = recs[0]!;
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0) tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).trim();
  }
  const logoUrl = tags.l || undefined;
  const authorityUrl = tags.a || undefined;
  if (logoUrl && !/^https:\/\/.+\.svg(\?.*)?$/i.test(logoUrl)) errors.push('Logo (l=) must be an https URL to an SVG Tiny PS file.');
  if (!logoUrl && !authorityUrl) warnings.push('BIMI record has no logo or certificate; it declines BIMI.');
  if (authorityUrl && !/^https:\/\//i.test(authorityUrl)) errors.push('Certificate (a=) must be an https URL to a VMC or CMC.');
  if (!authorityUrl) warnings.push('No VMC/CMC certificate (a=): Gmail and Apple Mail will not show your logo without one.');
  if (dmarc && dmarc.effectivePolicy !== 'quarantine' && dmarc.effectivePolicy !== 'reject') {
    errors.push('BIMI only works when DMARC is enforced (p=quarantine or p=reject, without t=y).');
  }
  return {
    domain,
    status: errors.length ? 'invalid' : 'ok',
    record,
    ...(logoUrl ? { logoUrl } : {}),
    ...(authorityUrl ? { authorityUrl } : {}),
    errors,
    warnings,
  };
}
