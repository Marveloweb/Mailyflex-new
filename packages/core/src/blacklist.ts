/**
 * DNS blocklist (DNSBL / RBL) checks over DoH.
 * Note: Spamhaus refuses queries arriving via large public resolvers (returns 127.255.255.25x);
 * those results are reported as "unknown", never as "listed".
 */
import { reverseIpName, type Resolver } from './dns.ts';
import { isIPv4 } from './ip.ts';

export interface Blocklist {
  zone: string;
  name: string;
  kind: 'ip' | 'domain';
  delistUrl: string;
  /** Answers that mean "query refused / rate limited", not a listing. */
  refusedPrefix?: string[];
}

export const IP_BLOCKLISTS: Blocklist[] = [
  { zone: 'zen.spamhaus.org', name: 'Spamhaus ZEN', kind: 'ip', delistUrl: 'https://check.spamhaus.org/', refusedPrefix: ['127.255.255.'] },
  { zone: 'b.barracudacentral.org', name: 'Barracuda', kind: 'ip', delistUrl: 'https://www.barracudacentral.org/rbl/removal-request' },
  { zone: 'bl.spamcop.net', name: 'SpamCop', kind: 'ip', delistUrl: 'https://www.spamcop.net/bl.shtml' },
  { zone: 'psbl.surriel.com', name: 'PSBL', kind: 'ip', delistUrl: 'https://psbl.org/' },
  { zone: 'dnsbl-1.uceprotect.net', name: 'UCEPROTECT L1', kind: 'ip', delistUrl: 'https://www.uceprotect.net/en/rblcheck.php' },
  { zone: 'bl.mailspike.net', name: 'Mailspike', kind: 'ip', delistUrl: 'https://mailspike.org/iplookup.html' },
  { zone: 'ix.dnsbl.manitu.net', name: 'NiX Spam', kind: 'ip', delistUrl: 'https://www.nixspam.net/' },
  { zone: 'dnsbl.dronebl.org', name: 'DroneBL', kind: 'ip', delistUrl: 'https://dronebl.org/lookup' },
  { zone: 'truncate.gbudb.net', name: 'GBUdb Truncate', kind: 'ip', delistUrl: 'https://www.gbudb.com/truncate/' },
  { zone: 'all.s5h.net', name: 's5h.net', kind: 'ip', delistUrl: 'https://www.usenix.org.uk/content/rbl.html' },
];

export const DOMAIN_BLOCKLISTS: Blocklist[] = [
  { zone: 'dbl.spamhaus.org', name: 'Spamhaus DBL', kind: 'domain', delistUrl: 'https://check.spamhaus.org/', refusedPrefix: ['127.255.255.'] },
  { zone: 'multi.surbl.org', name: 'SURBL', kind: 'domain', delistUrl: 'https://surbl.org/surbl-analysis' },
  { zone: 'multi.uribl.com', name: 'URIBL', kind: 'domain', delistUrl: 'https://admin.uribl.com/', refusedPrefix: ['127.0.0.1'] },
];

export interface BlocklistResult {
  zone: string;
  name: string;
  target: string;
  status: 'listed' | 'clean' | 'unknown';
  codes: string[];
  reason?: string;
  delistUrl: string;
}

async function checkOne(target: string, query: string, bl: Blocklist, resolver: Resolver): Promise<BlocklistResult> {
  const base = { zone: bl.zone, name: bl.name, target, delistUrl: bl.delistUrl };
  const r = await resolver.query(`${query}.${bl.zone}`, 'A');
  if (r.status === 'NXDOMAIN' || (r.status === 'NOERROR' && r.answers.length === 0)) return { ...base, status: 'clean', codes: [] };
  if (r.status !== 'NOERROR') return { ...base, status: 'unknown', codes: [], reason: 'Lookup failed.' };
  const codes = r.answers.map((a) => a.data);
  if (codes.some((c) => bl.refusedPrefix?.some((p) => c.startsWith(p) || c === p))) {
    return { ...base, status: 'unknown', codes, reason: 'This list refused the query from a public resolver.' };
  }
  if (!codes.some((c) => c.startsWith('127.'))) return { ...base, status: 'unknown', codes, reason: 'Unexpected answer.' };
  return { ...base, status: 'listed', codes };
}

export async function checkIpBlocklists(ip: string, resolver: Resolver, lists = IP_BLOCKLISTS): Promise<BlocklistResult[]> {
  if (!isIPv4(ip)) {
    // Most DNSBLs only cover IPv4. Report unknown rather than a false "clean".
    return lists.map((bl) => ({ zone: bl.zone, name: bl.name, target: ip, status: 'unknown', codes: [], reason: 'IPv6 not supported by this list.', delistUrl: bl.delistUrl }));
  }
  const rev = reverseIpName(ip)!;
  return Promise.all(lists.map((bl) => checkOne(ip, rev, bl, resolver)));
}

export async function checkDomainBlocklists(domain: string, resolver: Resolver, lists = DOMAIN_BLOCKLISTS): Promise<BlocklistResult[]> {
  return Promise.all(lists.map((bl) => checkOne(domain, domain, bl, resolver)));
}

export interface BlacklistAnalysis {
  domain: string;
  checkedIps: string[];
  results: BlocklistResult[];
  listed: BlocklistResult[];
}

/** Check the domain itself plus its MX/sending IPs. */
export async function analyzeBlacklists(domain: string, ips: string[], resolver: Resolver): Promise<BlacklistAnalysis> {
  const uniq = [...new Set(ips.filter(isIPv4))].slice(0, 10);
  const all = await Promise.all([checkDomainBlocklists(domain, resolver), ...uniq.map((ip) => checkIpBlocklists(ip, resolver))]);
  const results = all.flat();
  return { domain, checkedIps: uniq, results, listed: results.filter((r) => r.status === 'listed') };
}
