/**
 * DMARC aggregate report parsing: RFC 7489 Appendix C and RFC 9990 (namespace dmarc-2.0).
 * Attachments arrive as .xml, .xml.gz or .zip.
 */
import { XMLParser } from 'fast-xml-parser';
import { gunzipSync, unzipSync, strFromU8 } from 'fflate';

export type AuthResult = 'pass' | 'fail' | 'none' | 'neutral' | 'policy' | 'temperror' | 'permerror' | 'softfail' | string;

export interface AggregateRecord {
  sourceIp: string;
  count: number;
  disposition: 'none' | 'quarantine' | 'reject' | string;
  dkimAligned: boolean;
  spfAligned: boolean;
  reasons: { type: string; comment?: string }[];
  headerFrom: string;
  envelopeFrom?: string;
  envelopeTo?: string;
  dkim: { domain: string; selector?: string; result: AuthResult }[];
  spf: { domain: string; scope?: string; result: AuthResult }[];
}

export interface AggregateReport {
  orgName: string;
  email?: string;
  reportId: string;
  dateBegin: Date;
  dateEnd: Date;
  errors: string[];
  policy: {
    domain: string;
    adkim?: string;
    aspf?: string;
    p?: string;
    sp?: string;
    np?: string;
    pct?: number;
    testing?: string;
    discoveryMethod?: string;
  };
  records: AggregateRecord[];
}

const ARRAY_PATHS = new Set(['feedback.record', 'feedback.record.auth_results.dkim', 'feedback.record.auth_results.spf', 'feedback.record.row.policy_evaluated.reason', 'feedback.report_metadata.error']);

const parser = new XMLParser({
  ignoreAttributes: true,
  removeNSPrefix: true,
  parseTagValue: false,
  trimValues: true,
  processEntities: true,
  isArray: (_name, jpath) => ARRAY_PATHS.has(String(jpath)),
});

type Node = Record<string, unknown>;

function str(v: unknown): string | undefined {
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'object') return undefined;
  const s = String(v).trim();
  return s === '' ? undefined : s;
}

function obj(v: unknown): Node {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Node) : {};
}

function arr(v: unknown): Node[] {
  return Array.isArray(v) ? (v as Node[]) : v ? [v as Node] : [];
}

export class ReportParseError extends Error {}

export function parseAggregateReport(xml: string): AggregateReport {
  let doc: Node;
  try {
    doc = parser.parse(xml) as Node;
  } catch (e) {
    throw new ReportParseError(`Invalid XML: ${e instanceof Error ? e.message : String(e)}`);
  }
  const fb = obj(doc.feedback);
  if (!doc.feedback) throw new ReportParseError('Not a DMARC aggregate report (no <feedback> element).');
  const meta = obj(fb.report_metadata);
  const range = obj(meta.date_range);
  const pp = obj(fb.policy_published);
  const orgName = str(meta.org_name);
  const reportId = str(meta.report_id);
  const begin = Number(str(range.begin));
  const end = Number(str(range.end));
  const domain = str(pp.domain);
  if (!orgName || !reportId || !domain || !Number.isFinite(begin) || !Number.isFinite(end)) {
    throw new ReportParseError('Report is missing org_name, report_id, date_range or policy_published/domain.');
  }
  const records: AggregateRecord[] = arr(fb.record).map((r) => {
    const row = obj(r.row);
    const pe = obj(row.policy_evaluated);
    const ids = obj(r.identifiers);
    const auth = obj(r.auth_results);
    const envelopeFrom = str(ids.envelope_from);
    const envelopeTo = str(ids.envelope_to);
    return {
      sourceIp: str(row.source_ip) ?? '',
      count: Number(str(row.count) ?? 0),
      disposition: (str(pe.disposition) ?? 'none').toLowerCase(),
      dkimAligned: (str(pe.dkim) ?? '').toLowerCase() === 'pass',
      spfAligned: (str(pe.spf) ?? '').toLowerCase() === 'pass',
      reasons: arr(pe.reason).map((x) => {
        const comment = str(x.comment);
        return { type: str(x.type) ?? 'other', ...(comment ? { comment } : {}) };
      }),
      headerFrom: (str(ids.header_from) ?? domain).toLowerCase(),
      ...(envelopeFrom ? { envelopeFrom: envelopeFrom.toLowerCase() } : {}),
      ...(envelopeTo ? { envelopeTo: envelopeTo.toLowerCase() } : {}),
      dkim: arr(auth.dkim).map((d) => {
        const selector = str(d.selector);
        return { domain: (str(d.domain) ?? '').toLowerCase(), ...(selector ? { selector } : {}), result: (str(d.result) ?? 'none').toLowerCase() };
      }),
      spf: arr(auth.spf).map((s) => {
        const scope = str(s.scope);
        return { domain: (str(s.domain) ?? '').toLowerCase(), ...(scope ? { scope } : {}), result: (str(s.result) ?? 'none').toLowerCase() };
      }),
    };
  });
  const pct = str(pp.pct);
  const email = str(meta.email);
  const policy: AggregateReport['policy'] = { domain: domain.toLowerCase() };
  for (const k of ['adkim', 'aspf', 'p', 'sp', 'np', 'testing'] as const) {
    const v = str(pp[k]);
    if (v) policy[k] = v;
  }
  const dm = str(pp.discovery_method);
  if (dm) policy.discoveryMethod = dm;
  if (pct) policy.pct = Number(pct);
  return {
    orgName,
    ...(email ? { email } : {}),
    reportId,
    dateBegin: new Date(begin * 1000),
    dateEnd: new Date(end * 1000),
    errors: arr(meta.error).map((e) => String(e)),
    policy,
    records: records.filter((r) => r.sourceIp && r.count > 0),
  };
}

const MAX_UNCOMPRESSED = 50 * 1024 * 1024;

/** Turn an attachment (xml / gzip / zip) into one or more XML strings. */
export function unpackReport(bytes: Uint8Array): string[] {
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    const out = gunzipSync(bytes);
    if (out.length > MAX_UNCOMPRESSED) throw new ReportParseError('Decompressed report is too large.');
    return [strFromU8(out)];
  }
  if (bytes.length >= 4 && bytes[0] === 0x50 && bytes[1] === 0x4b) {
    let total = 0;
    const files = unzipSync(bytes, {
      filter: (f) => {
        total += f.originalSize;
        if (total > MAX_UNCOMPRESSED) throw new ReportParseError('Decompressed report is too large.');
        return /\.xml$/i.test(f.name) || !f.name.includes('.');
      },
    });
    return Object.values(files).map((f) => strFromU8(f));
  }
  return [strFromU8(bytes)];
}

export interface ReportSummary {
  total: number;
  passing: number;
  dkimAligned: number;
  spfAligned: number;
  quarantined: number;
  rejected: number;
  passRate: number;
}

export function summarizeRecords(records: Pick<AggregateRecord, 'count' | 'dkimAligned' | 'spfAligned' | 'disposition'>[]): ReportSummary {
  const s = { total: 0, passing: 0, dkimAligned: 0, spfAligned: 0, quarantined: 0, rejected: 0, passRate: 0 };
  for (const r of records) {
    s.total += r.count;
    if (r.dkimAligned || r.spfAligned) s.passing += r.count;
    if (r.dkimAligned) s.dkimAligned += r.count;
    if (r.spfAligned) s.spfAligned += r.count;
    if (r.disposition === 'quarantine') s.quarantined += r.count;
    if (r.disposition === 'reject') s.rejected += r.count;
  }
  s.passRate = s.total ? s.passing / s.total : 0;
  return s;
}
