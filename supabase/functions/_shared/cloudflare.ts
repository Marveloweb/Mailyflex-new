import { parseTxtData, toTxtStrings, type ZoneRecord } from '@mailyflex/core';
import { env } from './env.ts';

const API = 'https://api.cloudflare.com/client/v4';

interface CfRecord {
  id: string;
  name: string;
  type: string;
  content: string;
}

async function cf<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${env('CLOUDFLARE_API_TOKEN')}`, 'Content-Type': 'application/json', ...(init.headers ?? {}) },
  });
  const body = (await res.json()) as { success: boolean; errors?: { message: string }[]; result: T; result_info?: { total_pages: number } };
  if (!res.ok || !body.success) throw new Error(`Cloudflare ${init.method ?? 'GET'} ${path} failed: ${body.errors?.map((e) => e.message).join('; ') ?? res.status}`);
  return body.result;
}

const zoneId = () => env('CLOUDFLARE_ZONE_ID');

/** All TXT records whose name starts with `prefix` (e.g. a domain's token). */
export async function listTxtRecords(prefix: string): Promise<CfRecord[]> {
  const out: CfRecord[] = [];
  for (let page = 1; page <= 20; page++) {
    const batch = await cf<CfRecord[]>(`/zones/${zoneId()}/dns_records?type=TXT&per_page=100&page=${page}&name.startswith=${encodeURIComponent(prefix)}`);
    out.push(...batch.filter((r) => r.name.startsWith(`${prefix}.`) || r.name.startsWith(`${prefix}-`)));
    if (batch.length < 100) break;
  }
  return out;
}

function encodeContent(value: string): string {
  return value.length > 255 ? toTxtStrings(value) : value;
}

/** Make the zone match `desired` for names starting with `prefix`. Returns counts. */
export async function reconcileTxt(prefix: string, desired: ZoneRecord[]): Promise<{ created: number; updated: number; deleted: number }> {
  const existing = await listTxtRecords(prefix);
  const byName = new Map<string, CfRecord[]>();
  for (const r of existing) byName.set(r.name, [...(byName.get(r.name) ?? []), r]);
  const counts = { created: 0, updated: 0, deleted: 0 };
  const wanted = new Set(desired.map((d) => d.name));
  for (const d of desired) {
    const [first, ...dupes] = byName.get(d.name) ?? [];
    if (!first) {
      await cf(`/zones/${zoneId()}/dns_records`, { method: 'POST', body: JSON.stringify({ type: 'TXT', name: d.name, content: encodeContent(d.content), ttl: 300 }) });
      counts.created++;
    } else if (parseTxtData(first.content) !== d.content) {
      await cf(`/zones/${zoneId()}/dns_records/${first.id}`, { method: 'PATCH', body: JSON.stringify({ content: encodeContent(d.content), ttl: 300 }) });
      counts.updated++;
    }
    for (const dup of dupes) {
      await cf(`/zones/${zoneId()}/dns_records/${dup.id}`, { method: 'DELETE' });
      counts.deleted++;
    }
  }
  for (const r of existing) {
    if (!wanted.has(r.name)) {
      await cf(`/zones/${zoneId()}/dns_records/${r.id}`, { method: 'DELETE' });
      counts.deleted++;
    }
  }
  return counts;
}

interface CustomHostname {
  id: string;
  hostname: string;
  status: string;
  ssl?: { status: string };
}

/** Cloudflare for SaaS custom hostname so the Worker can serve https://mta-sts.<domain>. */
export async function ensureCustomHostname(hostname: string): Promise<CustomHostname> {
  const found = await cf<CustomHostname[]>(`/zones/${zoneId()}/custom_hostnames?hostname=${encodeURIComponent(hostname)}`);
  if (found[0]) return found[0];
  return cf<CustomHostname>(`/zones/${zoneId()}/custom_hostnames`, {
    method: 'POST',
    body: JSON.stringify({ hostname, ssl: { method: 'http', type: 'dv', settings: { min_tls_version: '1.2' } } }),
  });
}

export async function removeCustomHostname(hostname: string): Promise<void> {
  const found = await cf<CustomHostname[]>(`/zones/${zoneId()}/custom_hostnames?hostname=${encodeURIComponent(hostname)}`);
  for (const h of found) await cf(`/zones/${zoneId()}/custom_hostnames/${h.id}`, { method: 'DELETE' });
}
