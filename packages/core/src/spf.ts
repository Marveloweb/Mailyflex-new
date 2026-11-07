/**
 * SPF (RFC 7208): parsing, validation, recursive lookup counting, and macro-free flattening.
 */
import { resolveTxt, type Resolver } from './dns.ts';
import { compactCidrs, isValidCidr } from './ip.ts';

export type SpfQualifier = '+' | '-' | '~' | '?';
export type SpfMechanismName = 'all' | 'include' | 'a' | 'mx' | 'ptr' | 'ip4' | 'ip6' | 'exists';

export interface SpfMechanism {
  kind: 'mechanism';
  raw: string;
  qualifier: SpfQualifier;
  name: SpfMechanismName;
  value?: string;
  cidr4?: number;
  cidr6?: number;
}

export interface SpfModifier {
  kind: 'modifier';
  raw: string;
  name: string;
  value: string;
}

export type SpfTerm = SpfMechanism | SpfModifier;

export interface ParsedSpf {
  valid: boolean;
  terms: SpfTerm[];
  errors: string[];
  warnings: string[];
}

const MECHANISMS: SpfMechanismName[] = ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'];
const LOOKUP_MECHANISMS = new Set<string>(['include', 'a', 'mx', 'ptr', 'exists']);
export const SPF_LOOKUP_LIMIT = 10;
export const SPF_VOID_LIMIT = 2;

export function isSpfRecord(txt: string): boolean {
  return /^v=spf1(\s|$)/i.test(txt.trim());
}

export function parseSpf(record: string): ParsedSpf {
  const errors: string[] = [];
  const warnings: string[] = [];
  const terms: SpfTerm[] = [];
  const tokens = record.trim().split(/\s+/);
  if (!tokens[0] || tokens[0].toLowerCase() !== 'v=spf1') {
    return { valid: false, terms, errors: ['Record must start with "v=spf1".'], warnings };
  }
  let seenAll = false;
  let redirects = 0;
  let exps = 0;
  for (const raw of tokens.slice(1)) {
    const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
    if (mod) {
      const name = mod[1]!.toLowerCase();
      const value = mod[2]!;
      if (name === 'redirect') redirects++;
      if (name === 'exp') exps++;
      if ((name === 'redirect' || name === 'exp') && !value) errors.push(`"${raw}" needs a domain.`);
      terms.push({ kind: 'modifier', raw, name, value });
      continue;
    }
    const m = /^([+\-~?]?)([a-z0-9]+)(.*)$/i.exec(raw);
    const name = m?.[2]?.toLowerCase() as SpfMechanismName | undefined;
    if (!m || !name || !MECHANISMS.includes(name)) {
      errors.push(`Unknown term "${raw}".`);
      continue;
    }
    const qualifier = (m[1] || '+') as SpfQualifier;
    let rest = m[3] ?? '';
    const mech: SpfMechanism = { kind: 'mechanism', raw, qualifier, name };
    if (name === 'ip4' || name === 'ip6') {
      if (!rest.startsWith(':')) {
        errors.push(`"${raw}" needs an address.`);
        continue;
      }
      const value = rest.slice(1);
      if (!isValidCidr(value, name === 'ip4' ? 4 : 6)) {
        errors.push(`"${raw}" is not a valid ${name === 'ip4' ? 'IPv4' : 'IPv6'} address or range.`);
        continue;
      }
      mech.value = value;
    } else if (name === 'all') {
      if (rest) {
        errors.push(`"${raw}" takes no argument.`);
        continue;
      }
      seenAll = true;
    } else {
      const dual = /\/\/(\d+)$/.exec(rest);
      if (dual) {
        mech.cidr6 = Number(dual[1]);
        rest = rest.slice(0, dual.index);
      }
      const single = /\/(\d+)$/.exec(rest);
      if (single) {
        mech.cidr4 = Number(single[1]);
        rest = rest.slice(0, single.index);
      }
      if (rest.startsWith(':')) mech.value = rest.slice(1);
      else if (rest) {
        errors.push(`Malformed term "${raw}".`);
        continue;
      }
      if ((name === 'include' || name === 'exists') && !mech.value) {
        errors.push(`"${raw}" needs a domain.`);
        continue;
      }
      if ((mech.cidr4 ?? 0) > 32 || (mech.cidr6 ?? 0) > 128) {
        errors.push(`"${raw}" has an invalid prefix length.`);
        continue;
      }
      if (name === 'ptr') warnings.push('The "ptr" mechanism is slow and discouraged by RFC 7208; replace it with ip4/ip6 or include.');
    }
    if (seenAll && name !== 'all') warnings.push(`"${raw}" comes after "all" and will never be evaluated.`);
    terms.push(mech);
  }
  if (redirects > 1) errors.push('Only one "redirect=" modifier is allowed.');
  if (exps > 1) errors.push('Only one "exp=" modifier is allowed.');
  if (seenAll && redirects) warnings.push('"redirect=" is ignored because the record contains "all".');
  return { valid: errors.length === 0, terms, errors, warnings };
}

export interface SpfNode {
  domain: string;
  via: string; // mechanism that brought us here, e.g. "include:_spf.google.com" or "root"
  record?: string;
  lookups: number; // lookups caused directly by this node's terms
  children: SpfNode[];
  error?: string;
}

export interface SpfAnalysis {
  domain: string;
  status: 'ok' | 'missing' | 'multiple' | 'invalid' | 'error';
  record?: string;
  records: string[];
  parsed?: ParsedSpf;
  lookupCount: number;
  voidCount: number;
  tree?: SpfNode;
  ip4: string[];
  ip6: string[];
  /** Terms that can't be flattened to IPs (macros, exists, ptr) and must be kept verbatim. */
  unflattenable: string[];
  allQualifier?: SpfQualifier;
  errors: string[];
  warnings: string[];
}

interface WalkCtx {
  resolver: Resolver;
  lookups: number;
  voids: number;
  ip4: string[];
  ip6: string[];
  unflattenable: string[];
  errors: string[];
  warnings: string[];
  visited: Set<string>;
}

async function resolveAddrs(ctx: WalkCtx, host: string, m: SpfMechanism): Promise<boolean> {
  const [a, aaaa] = await Promise.all([ctx.resolver.query(host, 'A'), ctx.resolver.query(host, 'AAAA')]);
  for (const r of a.answers) ctx.ip4.push(m.cidr4 !== undefined ? `${r.data}/${m.cidr4}` : r.data);
  for (const r of aaaa.answers) ctx.ip6.push(m.cidr6 !== undefined ? `${r.data}/${m.cidr6}` : r.data);
  return a.answers.length + aaaa.answers.length > 0;
}

async function walk(domain: string, via: string, ctx: WalkCtx, depth: number, collectIps: boolean): Promise<SpfNode> {
  const node: SpfNode = { domain, via, lookups: 0, children: [] };
  const key = domain.toLowerCase();
  if (ctx.visited.has(key)) {
    node.error = `Loop: ${domain} is included more than once in the chain.`;
    ctx.errors.push(node.error);
    return node;
  }
  if (depth > 12) {
    node.error = 'Include chain is too deep.';
    ctx.errors.push(node.error);
    return node;
  }
  ctx.visited.add(key);
  const txt = await resolveTxt(ctx.resolver, domain);
  if (txt.status === 'ERROR' || txt.status === 'SERVFAIL') {
    node.error = `DNS lookup for ${domain} failed (temporary error).`;
    ctx.errors.push(node.error);
    return node;
  }
  const spfs = txt.records.filter(isSpfRecord);
  if (spfs.length === 0) {
    node.error = `${domain} has no SPF record.`;
    if (depth > 0) {
      if (txt.records.length === 0) ctx.voids++;
      ctx.errors.push(`${via} points to ${domain}, which has no SPF record (PermError).`);
    }
    return node;
  }
  if (spfs.length > 1 && depth > 0) {
    node.error = `${domain} publishes ${spfs.length} SPF records; only one is allowed.`;
    ctx.errors.push(node.error);
  }
  node.record = spfs[0]!;
  const parsed = parseSpf(node.record);
  if (depth > 0) {
    for (const e of parsed.errors) ctx.errors.push(`${domain}: ${e}`);
  }
  const hasAll = parsed.terms.some((t) => t.kind === 'mechanism' && t.name === 'all');
  for (const t of parsed.terms) {
    if (t.kind === 'modifier') {
      if (t.name === 'redirect' && !hasAll) {
        ctx.lookups++;
        node.lookups++;
        if (t.value.includes('%{')) {
          ctx.unflattenable.push(t.raw);
          continue;
        }
        node.children.push(await walk(t.value, t.raw, ctx, depth + 1, collectIps));
      }
      continue;
    }
    if (LOOKUP_MECHANISMS.has(t.name)) {
      ctx.lookups++;
      node.lookups++;
    }
    const isPass = t.qualifier === '+';
    const target = t.value ?? domain;
    if (t.name === 'ip4' || t.name === 'ip6') {
      if (collectIps && isPass) (t.name === 'ip4' ? ctx.ip4 : ctx.ip6).push(t.value!);
      else if (collectIps && depth > 0) ctx.unflattenable.push(t.raw);
      continue;
    }
    if (t.name === 'all') continue;
    if (target.includes('%{') || t.name === 'exists' || t.name === 'ptr') {
      if (collectIps) ctx.unflattenable.push(t.raw);
      if (t.name === 'exists' && !target.includes('%{')) {
        const r = await ctx.resolver.query(target, 'A');
        if (r.answers.length === 0) ctx.voids++;
      }
      continue;
    }
    if (t.name === 'include') {
      node.children.push(await walk(target, t.raw, ctx, depth + 1, collectIps && isPass));
      continue;
    }
    if (t.name === 'a') {
      const found = await resolveAddrs(ctx, target, t);
      if (!found) ctx.voids++;
      continue;
    }
    if (t.name === 'mx') {
      const mx = await ctx.resolver.query(target, 'MX');
      const hosts = mx.answers.map((a) => a.data.split(/\s+/)[1] ?? '').filter((h) => h && h !== '.');
      if (hosts.length === 0) ctx.voids++;
      if (hosts.length > 10) ctx.errors.push(`${target} has more than 10 MX hosts; the "mx" mechanism fails (PermError).`);
      for (const h of hosts.slice(0, 10)) await resolveAddrs(ctx, h, t);
    }
  }
  return node;
}

export interface AnalyzeSpfOptions {
  /** Analyze this record instead of the one published in DNS (used by the generator preview). */
  recordOverride?: string;
}

export async function analyzeSpf(domain: string, resolver: Resolver, opts: AnalyzeSpfOptions = {}): Promise<SpfAnalysis> {
  const base: SpfAnalysis = { domain, status: 'ok', records: [], lookupCount: 0, voidCount: 0, ip4: [], ip6: [], unflattenable: [], errors: [], warnings: [] };
  let records: string[];
  if (opts.recordOverride !== undefined) {
    records = [opts.recordOverride];
  } else {
    const txt = await resolveTxt(resolver, domain);
    if (txt.status === 'ERROR' || txt.status === 'SERVFAIL') {
      return { ...base, status: 'error', errors: [`DNS lookup failed: ${txt.error ?? txt.status}`] };
    }
    records = txt.records.filter(isSpfRecord);
  }
  base.records = records;
  if (records.length === 0) {
    return { ...base, status: 'missing', errors: ['No SPF record found. Receivers cannot tell which servers may send mail for this domain.'] };
  }
  if (records.length > 1) {
    base.status = 'multiple';
    base.errors.push(`Found ${records.length} SPF records. Only one is allowed, so receivers return PermError. Merge them into a single record.`);
  }
  const record = records[0]!;
  const parsed = parseSpf(record);
  base.record = record;
  base.parsed = parsed;
  base.errors.push(...parsed.errors);
  base.warnings.push(...parsed.warnings);
  if (!parsed.valid && base.status === 'ok') base.status = 'invalid';

  const ctx: WalkCtx = { resolver, lookups: 0, voids: 0, ip4: [], ip6: [], unflattenable: [], errors: [], warnings: [], visited: new Set() };
  // Root record may be an override; walk its children manually by stubbing a resolver layer.
  const rootResolver: Resolver = {
    query: (n, t) =>
      t === 'TXT' && n.toLowerCase() === domain.toLowerCase() && opts.recordOverride !== undefined
        ? Promise.resolve({ status: 'NOERROR', answers: [{ name: n, type: 'TXT', ttl: 0, data: opts.recordOverride }] })
        : resolver.query(n, t),
  };
  ctx.resolver = rootResolver;
  base.tree = await walk(domain, 'root', ctx, 0, true);
  base.lookupCount = ctx.lookups;
  base.voidCount = ctx.voids;
  base.ip4 = compactCidrs(ctx.ip4, 4);
  base.ip6 = compactCidrs(ctx.ip6, 6);
  base.unflattenable = [...new Set(ctx.unflattenable)];
  base.errors.push(...ctx.errors);
  base.warnings.push(...ctx.warnings);

  const all = parsed.terms.find((t): t is SpfMechanism => t.kind === 'mechanism' && t.name === 'all');
  base.allQualifier = all?.qualifier;
  if (ctx.lookups > SPF_LOOKUP_LIMIT) {
    base.errors.push(`Too many DNS lookups: ${ctx.lookups} of ${SPF_LOOKUP_LIMIT} allowed. Receivers return PermError and SPF fails for all mail.`);
  }
  if (ctx.voids > SPF_VOID_LIMIT) {
    base.errors.push(`Too many lookups that return nothing (${ctx.voids}; limit ${SPF_VOID_LIMIT}). Remove mechanisms that point to dead hosts.`);
  }
  if (all?.qualifier === '+') base.errors.push('"+all" lets every server on the internet send as this domain. Use "-all" or "~all".');
  if (all?.qualifier === '?') base.warnings.push('"?all" is neutral and gives no protection. Use "~all" or "-all".');
  if (!all && !parsed.terms.some((t) => t.kind === 'modifier' && t.name === 'redirect')) {
    base.warnings.push('No "all" mechanism: unlisted senders get a neutral result. End the record with "~all" or "-all".');
  }
  if (new TextEncoder().encode(record).length > 450) {
    base.warnings.push('Record is longer than 450 bytes; some resolvers may fall back to TCP or truncate it.');
  }
  if (base.status === 'ok' && base.errors.length) base.status = 'invalid';
  return base;
}

export interface FlattenOptions {
  /** Host of the first record, e.g. "<token>._s.dns.mailyflex.com". Next ones get "-1", "-2" appended to the first label. */
  baseHost: string;
  /** Terms that must be kept verbatim (macros, exists). */
  keep?: string[];
  maxBytes?: number;
}

export interface FlatRecord {
  host: string;
  value: string;
}

export function chunkHost(baseHost: string, index: number): string {
  if (index === 0) return baseHost;
  const [first, ...rest] = baseHost.split('.');
  return [`${first}-${index}`, ...rest].join('.');
}

/**
 * Build a chain of SPF records that together authorise exactly the given IPs.
 * Each record stays under maxBytes (default 450) and ends with include: of the next one.
 * Inner records carry no "all" so a non-match falls through to the customer's own "-all".
 */
export function flattenSpf(ip4: string[], ip6: string[], opts: FlattenOptions): FlatRecord[] {
  const maxBytes = opts.maxBytes ?? 450;
  const terms = [
    ...compactCidrs(ip4, 4).map((c) => `ip4:${c}`),
    ...compactCidrs(ip6, 6).map((c) => `ip6:${c}`),
    ...(opts.keep ?? []),
  ];
  const records: string[][] = [[]];
  const nextIncludeReserve = ` include:${chunkHost(opts.baseHost, 99)}`.length;
  for (const term of terms) {
    const cur = records[records.length - 1]!;
    const len = ['v=spf1', ...cur, term].join(' ').length + nextIncludeReserve;
    if (len > maxBytes && cur.length > 0) records.push([term]);
    else cur.push(term);
  }
  return records.map((termsI, i) => {
    const parts = ['v=spf1', ...termsI];
    if (i < records.length - 1) parts.push(`include:${chunkHost(opts.baseHost, i + 1)}`);
    return { host: chunkHost(opts.baseHost, i), value: parts.join(' ') };
  });
}

/** Split a TXT value into <=255-byte quoted strings for DNS providers. */
export function toTxtStrings(value: string): string {
  const parts: string[] = [];
  for (let i = 0; i < value.length; i += 255) parts.push(value.slice(i, i + 255));
  return parts.map((p) => `"${p.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join(' ');
}
