import type { SupabaseClient } from '@supabase/supabase-js';
import { appUrl, mailFrom, optionalEnv } from './env.ts';
import { escapeHtml, layout, sendEmail } from './resend.ts';

export interface NewAlert {
  org_id: string;
  domain_id?: string | null;
  kind: string;
  severity: 'critical' | 'warning' | 'info';
  title: string;
  body?: string;
  dedupe_key?: string | null;
}

/** Insert alerts, skipping ones whose dedupe key already exists. Returns the inserted rows. */
export async function createAlerts(db: SupabaseClient, alerts: NewAlert[]): Promise<(NewAlert & { id: number })[]> {
  if (!alerts.length) return [];
  const keyed = alerts.filter((a) => a.dedupe_key);
  const unkeyed = alerts.filter((a) => !a.dedupe_key);
  const out: (NewAlert & { id: number })[] = [];
  if (keyed.length) {
    const { data, error } = await db.from('alerts').upsert(keyed, { onConflict: 'org_id,dedupe_key', ignoreDuplicates: true }).select();
    if (error) throw error;
    out.push(...(data ?? []));
  }
  if (unkeyed.length) {
    const { data, error } = await db.from('alerts').insert(unkeyed).select();
    if (error) throw error;
    out.push(...(data ?? []));
  }
  return out;
}

export async function orgRecipients(db: SupabaseClient, orgId: string, minRole: 'viewer' | 'member' | 'admin' = 'admin'): Promise<string[]> {
  const roles = minRole === 'admin' ? ['admin', 'owner'] : minRole === 'member' ? ['member', 'admin', 'owner'] : ['viewer', 'member', 'admin', 'owner'];
  const { data: members } = await db.from('memberships').select('user_id').eq('org_id', orgId).in('role', roles);
  const ids = (members ?? []).map((m: { user_id: string }) => m.user_id);
  if (!ids.length) return [];
  const { data: profiles } = await db.from('profiles').select('email').in('id', ids);
  return (profiles ?? []).map((p: { email: string | null }) => p.email).filter((e): e is string => !!e);
}

/** Email critical alerts that have not been emailed yet (respects alert_settings). */
export async function emailPendingCritical(db: SupabaseClient, orgId: string): Promise<number> {
  if (!optionalEnv('RESEND_API_KEY')) return 0;
  const { data: settings } = await db.from('alert_settings').select('email_on_critical').eq('org_id', orgId).maybeSingle();
  if (settings && settings.email_on_critical === false) return 0;
  const { data: pending } = await db
    .from('alerts')
    .select('id, title, body, domain_id, created_at')
    .eq('org_id', orgId)
    .eq('severity', 'critical')
    .is('emailed_at', null)
    .order('created_at')
    .limit(20);
  if (!pending?.length) return 0;
  const to = await orgRecipients(db, orgId, 'admin');
  if (to.length) {
    const items = pending.map((a: { title: string; body: string }) => `<li style="margin-bottom:8px"><strong>${escapeHtml(a.title)}</strong><br>${escapeHtml(a.body)}</li>`).join('');
    await sendEmail({
      from: mailFrom(),
      to,
      subject: pending.length === 1 ? `Action needed: ${pending[0].title}` : `Action needed: ${pending.length} email security issues`,
      html: layout('Critical email security alerts', `<ul style="padding-left:18px">${items}</ul><p><a href="${appUrl()}/app/alerts" style="color:#0f766e">Open Maily Flex</a></p>`),
      text: pending.map((a: { title: string; body: string }) => `- ${a.title}\n  ${a.body}`).join('\n') + `\n\n${appUrl()}/app/alerts`,
      idempotencyKey: `critical-${orgId}-${pending.map((a: { id: number }) => a.id).join('-')}`.slice(0, 256),
    });
  }
  await db.from('alerts').update({ emailed_at: new Date().toISOString() }).in('id', pending.map((a: { id: number }) => a.id));
  return pending.length;
}
