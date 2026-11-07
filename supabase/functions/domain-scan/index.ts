// Scan one domain (member+) or every verified domain (cron).
import { handler, HttpError, json, readJson } from '../_shared/http.ts';
import { isCron, requireDomainRole, serviceClient, type DomainRow } from '../_shared/supabase.ts';
import { runScan } from '../_shared/scan.ts';

const BATCH = 4;
const BUDGET_MS = 110_000;

Deno.serve(
  handler(async (req) => {
    const body = await readJson<{ domain_id?: string; all?: boolean }>(req);
    const db = serviceClient();
    if (body.all) {
      if (!isCron(req)) throw new HttpError(401, 'Cron secret required');
      const started = Date.now();
      const { data: domains, error } = await db
        .from('domains')
        .select('*')
        .not('verified_at', 'is', null)
        .order('last_scan_at', { ascending: true, nullsFirst: true })
        .limit(200);
      if (error) throw error;
      let scanned = 0;
      const failures: string[] = [];
      const list = (domains ?? []) as DomainRow[];
      for (let i = 0; i < list.length && Date.now() - started < BUDGET_MS; i += BATCH) {
        const results = await Promise.allSettled(list.slice(i, i + BATCH).map((d) => runScan(db, d)));
        results.forEach((r, j) => (r.status === 'fulfilled' ? scanned++ : failures.push(`${list[i + j]!.name}: ${r.reason}`)));
      }
      if (failures.length) console.error('scan failures', failures);
      return json(req, { scanned, failed: failures.length, remaining: list.length - scanned - failures.length });
    }
    if (!body.domain_id) throw new HttpError(400, 'domain_id is required');
    const { domain } = await requireDomainRole(req, body.domain_id, 'member');
    // Light rate limit: one manual scan per domain per minute.
    if (domain.last_scan_at && Date.now() - Date.parse(domain.last_scan_at) < 60_000) {
      throw new HttpError(429, 'This domain was scanned less than a minute ago');
    }
    const result = await runScan(db, domain);
    return json(req, { score: result.score, grade: result.grade, scannedAt: result.scannedAt });
  }),
);
