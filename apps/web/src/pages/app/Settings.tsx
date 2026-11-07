import { useEffect, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { Button, CopyButton, Field, Input, Notice, Section, Select, Spinner } from '../../components/ui.tsx';
import { useAuth } from '../../lib/auth.tsx';
import { atLeast, useOrg, type Role } from '../../lib/org.tsx';
import { callFunction, db, errorMessage } from '../../lib/supabase.ts';

interface Member {
  user_id: string;
  role: Role;
  email: string | null;
  full_name: string | null;
}
interface Invite {
  id: string;
  email: string;
  role: Role;
  expires_at: string;
  accepted_at: string | null;
}

export function Settings() {
  const { current, reload: reloadOrgs } = useOrg();
  const { session } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState(current?.name ?? '');
  const [members, setMembers] = useState<Member[] | null>(null);
  const [invites, setInvites] = useState<Invite[]>([]);
  const [settings, setSettings] = useState<{ weekly_digest: boolean; email_on_critical: boolean; pass_rate_threshold: number } | null>(null);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<Role>('member');
  const [inviteLink, setInviteLink] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<{ status: 'pass' | 'fail'; text: string } | null>(null);
  const isAdmin = atLeast(current?.role, 'admin');
  const isOwner = current?.role === 'owner';

  const load = async () => {
    if (!current) return;
    const [{ data: m }, { data: inv }, { data: s }] = await Promise.all([
      db().from('memberships').select('user_id, role').eq('org_id', current.id),
      isAdmin ? db().from('invites').select('*').eq('org_id', current.id).is('accepted_at', null).order('created_at', { ascending: false }) : Promise.resolve({ data: [] }),
      db().from('alert_settings').select('*').eq('org_id', current.id).maybeSingle(),
    ]);
    const ids = (m ?? []).map((x: { user_id: string }) => x.user_id);
    const { data: profiles } = ids.length ? await db().from('profiles').select('id, email, full_name').in('id', ids) : { data: [] };
    setMembers(
      (m ?? []).map((x: { user_id: string; role: Role }) => {
        const p = (profiles ?? []).find((pp: { id: string }) => pp.id === x.user_id) as { email: string | null; full_name: string | null } | undefined;
        return { ...x, email: p?.email ?? null, full_name: p?.full_name ?? null };
      }),
    );
    setInvites((inv ?? []) as Invite[]);
    setSettings(s as typeof settings);
  };
  useEffect(() => {
    setName(current?.name ?? '');
    void load();
  }, [current?.id]); // reload only when the organization changes

  const run = async (key: string, fn: () => Promise<void>, ok?: string) => {
    setBusy(key);
    setMessage(null);
    try {
      await fn();
      if (ok) setMessage({ status: 'pass', text: ok });
    } catch (e) {
      setMessage({ status: 'fail', text: errorMessage(e) });
    } finally {
      setBusy(null);
    }
  };

  if (!current || !members) return <Spinner />;

  const rename = (e: FormEvent) => {
    e.preventDefault();
    void run(
      'rename',
      async () => {
        const { error } = await db().from('organizations').update({ name: name.trim() }).eq('id', current.id);
        if (error) throw error;
        await reloadOrgs();
      },
      'Organization renamed.',
    );
  };

  const invite = (e: FormEvent) => {
    e.preventDefault();
    setInviteLink(null);
    void run('invite', async () => {
      const r = await callFunction<{ emailed: boolean; link?: string }>('invite', { org_id: current.id, email: inviteEmail.trim(), role: inviteRole });
      setMessage({ status: 'pass', text: r.emailed ? `Invite sent to ${inviteEmail}.` : 'Invite created. Email is not configured, so share this link yourself:' });
      if (r.link) setInviteLink(r.link);
      setInviteEmail('');
      await load();
    });
  };

  return (
    <div className="space-y-12">
      <h1 className="text-3xl">Settings</h1>
      {message && (
        <div className="space-y-3">
          <Notice status={message.status}>{message.text}</Notice>
          {inviteLink && (
            <div className="flex items-center gap-2 rounded-lg border border-rule bg-sheet p-3">
              <code className="min-w-0 flex-1 font-mono text-sm break-all">{inviteLink}</code>
              <CopyButton value={inviteLink} label="Copy link" />
            </div>
          )}
        </div>
      )}

      <Section title="Organization">
        <form onSubmit={rename} className="flex max-w-lg gap-2">
          <label htmlFor="org-rename" className="sr-only">
            Organization name
          </label>
          <Input id="org-rename" value={name} onChange={(e) => setName(e.target.value)} disabled={!isAdmin} maxLength={100} />
          {isAdmin && (
            <Button type="submit" variant="secondary" busy={busy === 'rename'} disabled={!name.trim() || name === current.name}>
              Rename
            </Button>
          )}
        </form>
      </Section>

      <Section title="Team" description="Viewers can see everything. Members can also rescan. Admins manage domains, hosted records and the team. Owners can also delete the organization.">
        <table className="w-full text-left text-[15px]">
          <tbody>
            {members.map((m) => (
              <tr key={m.user_id} className="border-t border-rule">
                <td className="py-2.5">
                  <p className="font-medium">{m.full_name || m.email}</p>
                  {m.full_name && <p className="text-sm text-ink-soft">{m.email}</p>}
                </td>
                <td className="py-2.5">
                  {isAdmin && m.user_id !== session?.user.id && (m.role !== 'owner' || isOwner) ? (
                    <Select
                      aria-label={`Role for ${m.email}`}
                      value={m.role}
                      onChange={(e) =>
                        run('role', async () => {
                          const { error } = await db().from('memberships').update({ role: e.target.value }).eq('org_id', current.id).eq('user_id', m.user_id);
                          if (error) throw error;
                          await load();
                        })
                      }
                    >
                      <option value="viewer">Viewer</option>
                      <option value="member">Member</option>
                      <option value="admin">Admin</option>
                      {isOwner && <option value="owner">Owner</option>}
                    </Select>
                  ) : (
                    <span className="capitalize text-ink-soft">{m.role}</span>
                  )}
                </td>
                <td className="py-2.5 text-right">
                  {(m.user_id === session?.user.id || (isAdmin && (m.role !== 'owner' || isOwner))) && (
                    <button
                      className="text-sm text-ink-soft underline hover:text-fail"
                      onClick={() =>
                        run('remove', async () => {
                          const { error } = await db().from('memberships').delete().eq('org_id', current.id).eq('user_id', m.user_id);
                          if (error) throw error;
                          if (m.user_id === session?.user.id) {
                            await reloadOrgs();
                            navigate('/app');
                          } else await load();
                        })
                      }
                    >
                      {m.user_id === session?.user.id ? 'Leave' : 'Remove'}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {isAdmin && (
          <form onSubmit={invite} className="flex max-w-2xl flex-col gap-2 pt-2 sm:flex-row">
            <label htmlFor="invite-email" className="sr-only">
              Email
            </label>
            <Input id="invite-email" type="email" required value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} placeholder="teammate@yourcompany.com" />
            <Select aria-label="Role" value={inviteRole} onChange={(e) => setInviteRole(e.target.value as Role)}>
              <option value="viewer">Viewer</option>
              <option value="member">Member</option>
              <option value="admin">Admin</option>
            </Select>
            <Button type="submit" busy={busy === 'invite'} className="whitespace-nowrap">
              Send invite
            </Button>
          </form>
        )}
        {isAdmin && invites.length > 0 && (
          <div>
            <h3 className="mb-2 text-base">Pending invites</h3>
            <ul className="space-y-1 text-[15px]">
              {invites.map((i) => (
                <li key={i.id} className="flex items-center justify-between gap-3">
                  <span>
                    {i.email}{' '}
                    <span className="text-ink-soft">
                      as {i.role}, {new Date(i.expires_at) < new Date() ? 'expired' : `expires ${new Date(i.expires_at).toLocaleDateString('en', { month: 'short', day: 'numeric' })}`}
                    </span>
                  </span>
                  <button
                    className="text-sm text-ink-soft underline hover:text-fail"
                    onClick={() =>
                      run('revoke', async () => {
                        await db().from('invites').delete().eq('id', i.id);
                        await load();
                      })
                    }
                  >
                    Revoke
                  </button>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Section>

      {settings && (
        <Section title="Notifications">
          <div className="space-y-3">
            {(
              [
                ['email_on_critical', 'Email admins about critical alerts (records removed, blocklist listings, big pass-rate drops)'],
                ['weekly_digest', 'Send everyone a weekly digest on Mondays'],
              ] as const
            ).map(([key, label]) => (
              <label key={key} className="flex items-center gap-2 text-[15px]">
                <input
                  type="checkbox"
                  className="h-4 w-4 accent-[var(--color-ink)]"
                  disabled={!isAdmin}
                  checked={settings[key]}
                  onChange={(e) =>
                    run(key, async () => {
                      const { error } = await db().from('alert_settings').update({ [key]: e.target.checked }).eq('org_id', current.id);
                      if (error) throw error;
                      setSettings({ ...settings, [key]: e.target.checked });
                    })
                  }
                />
                {label}
              </label>
            ))}
            <Field label="Alert when DMARC pass rate falls below" htmlFor="threshold">
              <Select
                id="threshold"
                disabled={!isAdmin}
                value={String(settings.pass_rate_threshold)}
                onChange={(e) =>
                  run('threshold', async () => {
                    const v = Number(e.target.value);
                    const { error } = await db().from('alert_settings').update({ pass_rate_threshold: v }).eq('org_id', current.id);
                    if (error) throw error;
                    setSettings({ ...settings, pass_rate_threshold: v });
                  })
                }
              >
                {[0.8, 0.9, 0.95, 0.98, 0.99].map((v) => (
                  <option key={v} value={String(v)}>
                    {Math.round(v * 100)}%
                  </option>
                ))}
              </Select>
            </Field>
          </div>
        </Section>
      )}

      {isOwner && (
        <Section title="Delete organization" description="Deletes every domain, report and alert in this organization. Remove domains first if you use hosted records, so their DNS entries are cleaned up.">
          <Button
            variant="danger"
            busy={busy === 'delete'}
            onClick={() => {
              if (!window.confirm(`Delete ${current.name} and all its data? This cannot be undone.`)) return;
              void run('delete', async () => {
                const { error } = await db().from('organizations').delete().eq('id', current.id);
                if (error) throw error;
                await reloadOrgs();
                navigate('/app');
              });
            }}
          >
            Delete {current.name}
          </Button>
        </Section>
      )}
    </div>
  );
}
