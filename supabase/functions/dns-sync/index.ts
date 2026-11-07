// Publish hosted DMARC / SPF / MTA-STS / TLS-RPT records in the Maily Flex Cloudflare zone.
// POST {domain_id}                 admin: sync one domain
// POST {domain_id, action:"remove"} admin: remove hosted records, then delete the domain
// POST {all:true}                  cron: re-flatten SPF and resync every hosted domain
import { hostedEnv, optionalEnv } from '../_shared/env.ts';
import { handler, HttpError, json, readJson } from '../_shared/http.ts';
import { isCron, requireDomainRole, serviceClient, type DomainRow } from '../_shared/supabase.ts';
import { removeDomainRecords, syncDomain } from './sync.ts';

const configured = () => !!optionalEnv('CLOUDFLARE_API_TOKEN') && !!optionalEnv('CLOUDFLARE_ZONE_ID');

Deno.serve(
  handler(async (req) => {
    const body = await readJson<{ domain_id?: string; action?: 'sync' | 'remove'; all?: boolean }>(req);
    const db = serviceClient();
    const env = hostedEnv();

    if (body.all) {
      if (!isCron(req)) throw new HttpError(401, 'Cron secret required');
      if (!configured()) return json(req, { skipped: 'hosted DNS not configured' });
      const { data } = await db
        .from('domains')
        .select('*')
        .not('verified_at', 'is', null)
        .or('hosted_dmarc.eq.true,hosted_spf.eq.true,hosted_mta_sts.eq.true')
        .limit(500);
      const results = [];
      for (const d of (data ?? []) as DomainRow[]) {
        try {
          results.push(await syncDomain(db, d, env));
        } catch (e) {
          results.push({ domain: d.name, error: String(e) });
        }
      }
      return json(req, { synced: results.length, results });
    }

    if (!body.domain_id) throw new HttpError(400, 'domain_id is required');
    const { domain } = await requireDomainRole(req, body.domain_id, 'admin');

    if (body.action === 'remove') {
      const anyHosted = domain.hosted_dmarc || domain.hosted_spf || domain.hosted_mta_sts;
      if (anyHosted && configured()) await removeDomainRecords(domain);
      const { error } = await db.from('domains').delete().eq('id', domain.id);
      if (error) throw error;
      return json(req, { deleted: true });
    }

    if (!configured()) throw new HttpError(503, 'Hosted DNS is not configured on this server yet (Cloudflare credentials missing).');
    if (!domain.verified_at) throw new HttpError(409, 'Verify domain ownership before turning on hosted records.');
    return json(req, await syncDomain(db, domain, env));
  }),
);
