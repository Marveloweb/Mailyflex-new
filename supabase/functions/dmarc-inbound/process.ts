import { identifySender, lookupIpIntel, parseAggregateReport, unpackReport, type AggregateReport, type IpIntel, type Resolver } from '@mailyflex/core';

export interface InboundEvent {
  type: string;
  data: { email_id?: string; to?: string[] | string; from?: string; subject?: string };
}

export interface Attachment {
  filename: string;
  content_type: string;
  bytes: () => Promise<Uint8Array>;
}

export interface IngestDeps {
  ruaDomain: string;
  listAttachments: (emailId: string) => Promise<Attachment[]>;
  ingest: (token: string, report: unknown) => Promise<{ status: string; [k: string]: unknown }>;
  getIntel: (ips: string[]) => Promise<Map<string, IpIntel & { sender_key: string | null; updated_at: string }>>;
  saveIntel: (rows: (IpIntel & { sender_key: string | null })[]) => Promise<void>;
  resolver: Resolver;
  maxIntelLookups?: number;
}

export interface ProcessResult {
  token: string | null;
  reports: { file: string; status: string; reportId?: string; error?: string }[];
}

/** Extract the report token from the first recipient on our RUA domain: <token>[+tag]@rua.mailyflex.com */
export function tokenFromRecipients(to: string[] | string | undefined, ruaDomain: string): string | null {
  const list = Array.isArray(to) ? to : to ? [to] : [];
  for (const raw of list) {
    const m = /<?([^<>\s]+)@([^<>\s]+?)>?$/.exec(raw.trim());
    if (!m) continue;
    if (m[2]!.toLowerCase() !== ruaDomain.toLowerCase()) continue;
    const local = m[1]!.toLowerCase().split('+')[0]!;
    if (/^[a-f0-9]{8,64}$/.test(local)) return local;
  }
  return null;
}

const INTEL_MAX_AGE_MS = 30 * 86400_000;

/** Add senderKey to each record using auth domains, cached IP intel, and fresh PTR/ASN lookups. */
export async function enrichReport(report: AggregateReport, deps: IngestDeps) {
  const ips = [...new Set(report.records.map((r) => r.sourceIp))];
  const cached = await deps.getIntel(ips);
  const fresh: (IpIntel & { sender_key: string | null })[] = [];
  let budget = deps.maxIntelLookups ?? 40;
  const byVolume = [...report.records].sort((a, b) => b.count - a.count);
  const intelFor = new Map<string, { ptr: string | null; asn: number | null }>();
  for (const r of byVolume) {
    if (intelFor.has(r.sourceIp)) continue;
    const c = cached.get(r.sourceIp);
    if (c && Date.now() - Date.parse(c.updated_at) < INTEL_MAX_AGE_MS) {
      intelFor.set(r.sourceIp, c);
      continue;
    }
    if (budget-- <= 0) continue;
    const intel = await lookupIpIntel(r.sourceIp, deps.resolver).catch(() => null);
    if (intel) {
      intelFor.set(r.sourceIp, intel);
      fresh.push({ ...intel, sender_key: identifySender({ ptr: intel.ptr, asn: intel.asn })?.key ?? null });
    }
  }
  if (fresh.length) await deps.saveIntel(fresh);
  return {
    ...report,
    dateBegin: report.dateBegin.toISOString(),
    dateEnd: report.dateEnd.toISOString(),
    records: report.records.map((r) => {
      const intel = intelFor.get(r.sourceIp);
      const authDomains = [...r.dkim.filter((d) => d.result === 'pass').map((d) => d.domain), ...r.spf.filter((s) => s.result === 'pass').map((s) => s.domain)];
      const sender = identifySender({ authDomains, ptr: intel?.ptr ?? null, asn: intel?.asn ?? null });
      return { ...r, senderKey: sender?.key ?? null };
    }),
  };
}

export async function processInbound(event: InboundEvent, deps: IngestDeps): Promise<ProcessResult> {
  const token = tokenFromRecipients(event.data.to, deps.ruaDomain);
  const result: ProcessResult = { token, reports: [] };
  if (!token || !event.data.email_id) return result;
  const attachments = await deps.listAttachments(event.data.email_id);
  for (const a of attachments.slice(0, 10)) {
    if (!/\.(xml|gz|zip)$/i.test(a.filename) && !/(xml|gzip|zip|octet-stream)/i.test(a.content_type)) {
      result.reports.push({ file: a.filename, status: 'skipped' });
      continue;
    }
    try {
      const xmls = unpackReport(await a.bytes());
      for (const xml of xmls.slice(0, 5)) {
        const report = parseAggregateReport(xml);
        const enriched = await enrichReport(report, deps);
        const r = await deps.ingest(token, enriched);
        result.reports.push({ file: a.filename, status: r.status, reportId: report.reportId });
      }
    } catch (e) {
      result.reports.push({ file: a.filename, status: 'error', error: e instanceof Error ? e.message : String(e) });
    }
  }
  return result;
}
