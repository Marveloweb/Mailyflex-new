import { expandIPv6 } from './dns.ts';

export function isIPv4(ip: string): boolean {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  return !!m && m.slice(1).every((o) => Number(o) <= 255 && String(Number(o)) === o);
}

export function isIPv6(ip: string): boolean {
  return expandIPv6(ip) !== null;
}

export function isValidCidr(value: string, family: 4 | 6): boolean {
  const [ip, len, ...rest] = value.split('/');
  if (rest.length || !ip) return false;
  if (family === 4 ? !isIPv4(ip) : !isIPv6(ip)) return false;
  if (len === undefined) return true;
  if (!/^\d{1,3}$/.test(len)) return false;
  return Number(len) <= (family === 4 ? 32 : 128);
}

function ipToBigInt(ip: string, family: 4 | 6): bigint {
  if (family === 4) return ip.split('.').reduce((acc, o) => (acc << 8n) + BigInt(Number(o)), 0n);
  return BigInt('0x' + expandIPv6(ip)!.replace(/:/g, ''));
}

function bigIntToIp(n: bigint, family: 4 | 6): string {
  if (family === 4) return [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join('.');
  const hex = n.toString(16).padStart(32, '0');
  const groups = hex.match(/.{4}/g)!.map((g) => g.replace(/^0+(?=.)/, ''));
  // compress the longest run of zero groups
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== '0') {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > bestLen && j - i > 1) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  if (bestStart === -1) return groups.join(':');
  const left = groups.slice(0, bestStart).join(':');
  const right = groups.slice(bestStart + bestLen).join(':');
  return `${left}::${right}`;
}

interface Range {
  start: bigint;
  end: bigint;
}

function cidrToRange(cidr: string, family: 4 | 6): Range {
  const bits = family === 4 ? 32 : 128;
  const [ip, lenStr] = cidr.split('/');
  const len = lenStr === undefined ? bits : Number(lenStr);
  const host = BigInt(bits - len);
  const base = (ipToBigInt(ip!, family) >> host) << host;
  return { start: base, end: base + (1n << host) - 1n };
}

function rangeToCidrs(r: Range, family: 4 | 6): string[] {
  const bits = family === 4 ? 32 : 128;
  const out: string[] = [];
  let start = r.start;
  while (start <= r.end) {
    let size = 0;
    while (size < bits) {
      const next = size + 1;
      const mask = (1n << BigInt(next)) - 1n;
      if ((start & mask) !== 0n) break;
      if (start + (1n << BigInt(next)) - 1n > r.end) break;
      size = next;
    }
    const len = bits - size;
    out.push(len === bits ? bigIntToIp(start, family) : `${bigIntToIp(start, family)}/${len}`);
    start += 1n << BigInt(size);
  }
  return out;
}

/**
 * Deduplicate and merge CIDRs: removes contained ranges and joins adjacent ones,
 * producing the minimal equivalent CIDR list (sorted).
 */
export function compactCidrs(cidrs: string[], family: 4 | 6): string[] {
  const ranges = cidrs
    .filter((c) => isValidCidr(c, family))
    .map((c) => cidrToRange(c, family))
    .sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
  const merged: Range[] = [];
  for (const r of ranges) {
    const last = merged[merged.length - 1];
    if (last && r.start <= last.end + 1n) {
      if (r.end > last.end) last.end = r.end;
    } else {
      merged.push({ ...r });
    }
  }
  return merged.flatMap((r) => rangeToCidrs(r, family));
}

export function ipInCidr(ip: string, cidr: string): boolean {
  const family: 4 | 6 = isIPv4(ip) ? 4 : 6;
  if (!isValidCidr(cidr, family)) return false;
  const r = cidrToRange(cidr, family);
  const n = ipToBigInt(ip, family);
  return n >= r.start && n <= r.end;
}
