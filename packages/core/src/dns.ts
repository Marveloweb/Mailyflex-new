/**
 * DNS-over-HTTPS resolver. Works in browsers, Deno and Workers (only needs fetch).
 * A Resolver is injected everywhere so tests can use an in-memory zone.
 */

export type RRType = 'A' | 'AAAA' | 'MX' | 'TXT' | 'CNAME' | 'NS' | 'PTR' | 'SOA';

export const RR_TYPE_CODES: Record<RRType, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
};

export type DnsStatus = 'NOERROR' | 'NXDOMAIN' | 'SERVFAIL' | 'ERROR';

export interface DnsAnswer {
  name: string;
  type: RRType | number;
  ttl: number;
  data: string;
}

export interface DnsResult {
  status: DnsStatus;
  /** Answers of the requested type only (CNAME chain entries removed). */
  answers: DnsAnswer[];
  /** Name the answers finally came from after following CNAMEs, if any. */
  cnameTarget?: string;
  error?: string;
}

export interface Resolver {
  query(name: string, type: RRType): Promise<DnsResult>;
}

const STATUS_BY_CODE: Record<number, DnsStatus> = { 0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN' };

export function normalizeDomain(input: string): string {
  let d = input.trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, '');
  d = d.replace(/^.*@/, '');
  d = d.split('/')[0]!.split('?')[0]!.split('#')[0]!;
  d = d.replace(/:\d+$/, '');
  d = d.replace(/\.+$/, '');
  return d;
}

const LABEL = /^(?!-)[a-z0-9_-]{1,63}(?<!-)$/;

export function isValidDomain(domain: string): boolean {
  const d = normalizeDomain(domain);
  if (d.length < 3 || d.length > 253) return false;
  const labels = d.split('.');
  if (labels.length < 2) return false;
  if (!/^[a-z]{2,63}$|^xn--[a-z0-9-]{1,59}$/.test(labels[labels.length - 1]!)) return false;
  return labels.every((l) => LABEL.test(l));
}

/** Parse DoH TXT data: `"part one" "part two"` -> `part onepart two` (RFC 7208 §3.3 concatenation). */
export function parseTxtData(data: string): string {
  const s = data.trim();
  if (!s.startsWith('"')) return s;
  let out = '';
  let i = 0;
  while (i < s.length) {
    if (s[i] !== '"') {
      i++;
      continue;
    }
    i++;
    while (i < s.length && s[i] !== '"') {
      if (s[i] === '\\' && i + 1 < s.length) {
        const rest = s.slice(i + 1, i + 4);
        if (/^\d{3}$/.test(rest)) {
          out += String.fromCharCode(parseInt(rest, 10));
          i += 4;
          continue;
        }
        out += s[i + 1];
        i += 2;
        continue;
      }
      out += s[i];
      i++;
    }
    i++;
  }
  return out;
}

export interface DohOptions {
  endpoints?: string[];
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export const DEFAULT_DOH_ENDPOINTS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];

interface DohJson {
  Status: number;
  Answer?: { name: string; type: number; TTL: number; data: string }[];
}

export class DohResolver implements Resolver {
  private endpoints: string[];
  private fetchImpl: typeof fetch;
  private timeoutMs: number;

  constructor(opts: DohOptions = {}) {
    this.endpoints = opts.endpoints ?? DEFAULT_DOH_ENDPOINTS;
    this.fetchImpl = opts.fetchImpl ?? ((...args) => fetch(...args));
    this.timeoutMs = opts.timeoutMs ?? 5000;
  }

  async query(name: string, type: RRType): Promise<DnsResult> {
    let lastError = 'no endpoints';
    for (const endpoint of this.endpoints) {
      try {
        const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`;
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
        let res: Response;
        try {
          res = await this.fetchImpl(url, { headers: { accept: 'application/dns-json' }, signal: ctrl.signal });
        } finally {
          clearTimeout(timer);
        }
        if (!res.ok) {
          lastError = `HTTP ${res.status} from ${endpoint}`;
          continue;
        }
        const json = (await res.json()) as DohJson;
        const status = STATUS_BY_CODE[json.Status] ?? 'ERROR';
        if (status === 'SERVFAIL') {
          lastError = `SERVFAIL from ${endpoint}`;
          continue;
        }
        return toResult(status, json.Answer ?? [], type);
      } catch (e) {
        lastError = e instanceof Error ? e.message : String(e);
      }
    }
    return { status: 'ERROR', answers: [], error: lastError };
  }
}

function toResult(status: DnsStatus, raw: { name: string; type: number; TTL: number; data: string }[], type: RRType): DnsResult {
  const code = RR_TYPE_CODES[type];
  const answers: DnsAnswer[] = [];
  let cnameTarget: string | undefined;
  for (const a of raw) {
    if (a.type === RR_TYPE_CODES.CNAME && type !== 'CNAME') {
      cnameTarget = a.data.replace(/\.$/, '').toLowerCase();
      continue;
    }
    if (a.type !== code) continue;
    answers.push({
      name: a.name.replace(/\.$/, '').toLowerCase(),
      type,
      ttl: a.TTL,
      data: type === 'TXT' ? parseTxtData(a.data) : a.data.replace(/\.$/, '').toLowerCase(),
    });
  }
  return cnameTarget ? { status, answers, cnameTarget } : { status, answers };
}

/** Caches results for the lifetime of the instance (one scan). Dedupes concurrent identical queries. */
export class CachingResolver implements Resolver {
  private cache = new Map<string, Promise<DnsResult>>();
  queries = 0;
  constructor(private inner: Resolver) {}
  query(name: string, type: RRType): Promise<DnsResult> {
    const key = `${type} ${name.toLowerCase()}`;
    let p = this.cache.get(key);
    if (!p) {
      this.queries++;
      p = this.inner.query(name, type);
      this.cache.set(key, p);
    }
    return p;
  }
}

/** In-memory resolver for tests and offline use. Zone keys: "TXT example.com". */
export class StaticResolver implements Resolver {
  private zone: Record<string, string[]>;
  constructor(
    zone: Record<string, string[]>,
    private opts: { cnames?: Record<string, string>; servfail?: string[] } = {},
  ) {
    this.zone = Object.fromEntries(
      Object.entries(zone).map(([k, v]) => {
        const [t, n] = k.split(' ');
        return [`${t!.toUpperCase()} ${n!.toLowerCase()}`, v];
      }),
    );
  }
  async query(name: string, type: RRType): Promise<DnsResult> {
    let n = name.toLowerCase().replace(/\.$/, '');
    if (this.opts.servfail?.includes(n)) return { status: 'SERVFAIL', answers: [], error: 'SERVFAIL' };
    let cnameTarget: string | undefined;
    for (let hops = 0; hops < 8 && this.opts.cnames?.[n] && type !== 'CNAME'; hops++) {
      n = this.opts.cnames[n]!;
      cnameTarget = n;
    }
    if (type === 'CNAME' && this.opts.cnames?.[n]) {
      return { status: 'NOERROR', answers: [{ name: n, type, ttl: 300, data: this.opts.cnames[n]! }] };
    }
    const data = this.zone[`${type} ${n}`];
    const exists = Object.keys(this.zone).some((k) => k.split(' ')[1] === n || k.split(' ')[1]!.endsWith(`.${n}`));
    const status: DnsStatus = data || exists ? 'NOERROR' : 'NXDOMAIN';
    const answers = (data ?? []).map((d) => ({ name: n, type, ttl: 300, data: d }));
    return cnameTarget ? { status, answers, cnameTarget } : { status, answers };
  }
}

export async function resolveTxt(resolver: Resolver, name: string): Promise<{ status: DnsStatus; records: string[]; error?: string }> {
  const r = await resolver.query(name, 'TXT');
  return { status: r.status, records: r.answers.map((a) => a.data), ...(r.error ? { error: r.error } : {}) };
}

export function reverseIpName(ip: string): string | null {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return ip.split('.').reverse().join('.');
  const expanded = expandIPv6(ip);
  if (!expanded) return null;
  return expanded.replace(/:/g, '').split('').reverse().join('.');
}

export function expandIPv6(ip: string): string | null {
  if (!ip.includes(':')) return null;
  const [head, tail] = ip.split('::');
  if (ip.split('::').length > 2) return null;
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail !== '' ? tail.split(':') : [];
  const missing = 8 - h.length - t.length;
  if ((tail === undefined && h.length !== 8) || missing < 0) return null;
  const parts = [...h, ...Array(tail === undefined ? 0 : missing).fill('0'), ...t];
  if (parts.length !== 8 || !parts.every((p) => /^[0-9a-f]{1,4}$/i.test(p))) return null;
  return parts.map((p) => p.toLowerCase().padStart(4, '0')).join(':');
}
