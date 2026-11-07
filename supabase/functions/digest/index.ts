// Cron: daily pass-rate / new-sender alerts and critical-alert emails; weekly digest email.
import { appUrl, mailFrom, optionalEnv } from '../_shared/env.ts';
import { createAlerts, emailPendingCritical, orgRecipients, type NewAlert } from '../_shared/alerts.ts';
import { handler, HttpError, json, readJson } from '../_shared/http.ts';
import { escapeHtml, layout, sendEmail } from '../_shared/resend.ts';
import { isCron, serviceClient, type DomainRow } from '../_shared/supabase.ts';
import { senderByKey } from '@mailyflex/core';

type Stat = { day: string; total: number; passing: number };

function senderName(sender: string): string {
  return sender.startsWith('ip:') ? sender.slice(3) : (senderByKey(sender)?.name ?? sender);
}

Deno.serve(
  handler(async (req) => {
    if (!(await isCron(req))) throw new HttpError(401, 'Cron secret required');
    const { mode = 'daily' } = await readJson<{ mode?: 'daily' | 'weekly' }>(req);
    const db = serviceClient();
    const { data: domains } = await db.from('domains').select('*').not('verified_at', 'is', null).limit(2000);
    const byOrg = new Map<string, DomainRow[]>();
    for (const d of (domains ?? []) as DomainRow[]) byOrg.set(d.org_id, [...(byOrg.get(d.org_id) ?? []), d]);
    const { data: settingsRows } = await db.from('alert_settings').select('*');
    type Settings = { org_id: string; weekly_digest: boolean; pass_rate_threshold: number };
    const settings = new Map(((settingsRows ?? []) as Settings[]).map((s) => [s.org_id, s]));
    const today = new Date().toISOString().slice(0, 10);
    const summary = { orgs: 0, alerts: 0, emails: 0 };

    for (const [orgId, list] of byOrg) {
      summary.orgs++;
      const threshold = Number(settings.get(orgId)?.pass_rate_threshold ?? 0.95);
      const lines: string[] = [];
      for (const d of list) {
        const { data: stats } = await db.rpc('domain_daily_stats', { p_domain: d.id, p_days: mode === 'weekly' ? 7 : 2 });
        const rows = (stats ?? []) as Stat[];
        const total = rows.reduce((a, r) => a + Number(r.total), 0);
        const passing = rows.reduce((a, r) => a + Number(r.passing), 0);
        const rate = total ? passing / total : null;
        if (mode === 'daily') {
          const alerts: NewAlert[] = [];
          if (rate !== null && total >= 50 && rate < threshold) {
            alerts.push({
              org_id: orgId,
              domain_id: d.id,
              kind: 'pass_rate',
              severity: rate < threshold - 0.1 ? 'critical' : 'warning',
              title: `${d.name}: only ${(rate * 100).toFixed(1)}% of mail passed DMARC`,
              body: `${total - passing} of ${total} messages in the last 2 days failed SPF and DKIM alignment. Check the Senders tab for the source.`,
              dedupe_key: `pass:${d.id}:${today}`,
            });
          }
          const since = new Date(Date.now() - 2 * 86400_000).toISOString().slice(0, 10);
          const { data: fresh } = await db.rpc('domain_new_senders', { p_domain: d.id, p_since: since });
          // Skip "new sender" noise for the first days after reports start arriving.
          const { count: older } = await db.from('dmarc_records').select('id', { count: 'exact', head: true }).eq('domain_id', d.id).lt('day', since);
          for (const s of older ? ((fresh ?? []) as { sender: string; total: number; passing: number }[]) : []) {
            if (Number(s.total) < 5) continue;
            alerts.push({
              org_id: orgId,
              domain_id: d.id,
              kind: 'new_sender',
              severity: Number(s.passing) === Number(s.total) ? 'info' : 'warning',
              title: `${d.name}: new sender ${senderName(s.sender)}`,
              body: `${s.total} messages, ${s.passing} passing DMARC. If you don't recognise this service, it may be spoofing your domain.`,
              dedupe_key: `sender:${d.id}:${s.sender}`,
            });
          }
          summary.alerts += (await createAlerts(db, alerts)).length;
        } else {
          lines.push(
            `<tr><td style="padding:6px 0">${escapeHtml(d.name)}</td><td>${d.health_score ?? '–'} ${escapeHtml(d.grade ?? '')}</td><td>${total.toLocaleString('en')}</td><td>${rate === null ? '–' : `${(rate * 100).toFixed(1)}%`}</td></tr>`,
          );
        }
      }
      if (mode === 'daily') {
        summary.emails += await emailPendingCritical(db, orgId);
      } else if (settings.get(orgId)?.weekly_digest !== false && optionalEnv('RESEND_API_KEY') && lines.length) {
        const to = await orgRecipients(db, orgId, 'member');
        const { count: unread } = await db.from('alerts').select('id', { count: 'exact', head: true }).eq('org_id', orgId).is('read_at', null);
        if (to.length) {
          await sendEmail({
            from: mailFrom(),
            to,
            subject: 'Your weekly email security digest',
            html: layout(
              'Weekly digest',
              `<table width="100%" style="font-size:14px;border-collapse:collapse"><tr style="color:#6b7280;text-align:left"><th>Domain</th><th>Score</th><th>Messages (7d)</th><th>DMARC pass</th></tr>${lines.join('')}</table>
               <p>${unread ?? 0} unread alert(s). <a href="${appUrl()}/app" style="color:#0f766e">Open Maily Flex</a></p>`,
            ),
            text: `Weekly digest: ${list.length} domain(s), ${unread ?? 0} unread alert(s). ${appUrl()}/app`,
            idempotencyKey: `weekly-${orgId}-${today}`,
          });
          summary.emails++;
        }
      }
    }
    return json(req, { mode, ...summary });
  }),
);
