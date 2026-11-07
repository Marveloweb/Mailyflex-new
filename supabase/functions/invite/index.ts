// Invite a teammate: the database checks permissions and returns a one-time token; we email the link.
import { appUrl, mailFrom, optionalEnv } from '../_shared/env.ts';
import { escapeHtml, layout, sendEmail } from '../_shared/resend.ts';
import { handler, HttpError, json, readJson } from '../_shared/http.ts';
import { requireUser } from '../_shared/supabase.ts';

Deno.serve(
  handler(async (req) => {
    const { org_id, email, role } = await readJson<{ org_id?: string; email?: string; role?: string }>(req);
    if (!org_id || !email) throw new HttpError(400, 'org_id and email are required');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new HttpError(400, 'Enter a valid email address');
    const r = role ?? 'member';
    if (!['viewer', 'member', 'admin'].includes(r)) throw new HttpError(400, 'Role must be viewer, member or admin');
    const { user, client } = await requireUser(req);
    const { data: token, error } = await client.rpc('create_invite', { p_org: org_id, p_email: email, p_role: r });
    if (error) throw new HttpError(error.code === '42501' ? 403 : 400, error.message);
    const { data: org } = await client.from('organizations').select('name').eq('id', org_id).single();
    const link = `${appUrl()}/invite/${token}`;
    if (!optionalEnv('RESEND_API_KEY')) return json(req, { invited: true, emailed: false, link });
    const inviter = user.email ?? 'A teammate';
    await sendEmail({
      from: mailFrom(),
      to: [email.toLowerCase()],
      subject: `${inviter} invited you to ${org?.name ?? 'their team'} on Maily Flex`,
      html: layout(
        `Join ${org?.name ?? 'your team'} on Maily Flex`,
        `<p>${escapeHtml(inviter)} invited you as <strong>${escapeHtml(r)}</strong>.</p><p><a href="${link}" style="display:inline-block;background:#0f766e;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">Accept invite</a></p><p style="color:#6b7280;font-size:13px">The link expires in 7 days. Sign in with ${escapeHtml(email.toLowerCase())} to accept.</p>`,
      ),
      text: `${inviter} invited you to ${org?.name ?? 'their team'} on Maily Flex as ${r}.\nAccept: ${link}\nThe link expires in 7 days.`,
    });
    return json(req, { invited: true, emailed: true });
  }),
);
