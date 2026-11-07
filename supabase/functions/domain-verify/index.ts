// Verify domain ownership via TXT _mailyflex.<domain> = mailyflex-verify=<token>, then run the first scan.
import { DohResolver, resolveTxt, verificationRecord } from '@mailyflex/core';
import { handler, HttpError, json, readJson } from '../_shared/http.ts';
import { requireDomainRole, serviceClient } from '../_shared/supabase.ts';
import { runScan } from '../_shared/scan.ts';

Deno.serve(
  handler(async (req) => {
    const { domain_id } = await readJson<{ domain_id?: string }>(req);
    if (!domain_id) throw new HttpError(400, 'domain_id is required');
    const { domain } = await requireDomainRole(req, domain_id, 'admin');
    const db = serviceClient();
    const expected = verificationRecord(domain.name, domain.verification_token);
    if (!domain.verified_at) {
      const txt = await resolveTxt(new DohResolver(), expected.host);
      if (txt.status === 'ERROR' || txt.status === 'SERVFAIL') throw new HttpError(502, 'DNS lookup failed; try again in a minute');
      if (!txt.records.some((r) => r.trim() === expected.value)) {
        return json(req, { verified: false, expected, found: txt.records });
      }
      const { error } = await db.from('domains').update({ verified_at: new Date().toISOString() }).eq('id', domain.id);
      if (error) {
        if (error.code === '23505') throw new HttpError(409, 'This domain is already verified by another organization. Contact support if you own it.');
        throw error;
      }
      domain.verified_at = new Date().toISOString();
    }
    const scan = await runScan(db, domain);
    return json(req, { verified: true, score: scan.score, grade: scan.grade });
  }),
);
