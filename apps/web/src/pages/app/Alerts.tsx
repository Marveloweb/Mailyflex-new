import { useEffect, useState } from 'react';
import { Link } from 'react-router';
import { Badge, Button, EmptyState, Spinner, type Status } from '../../components/ui.tsx';
import { timeAgo } from '../../lib/format.ts';
import { useOrg } from '../../lib/org.tsx';
import { db } from '../../lib/supabase.ts';
import type { AlertRow } from '../../lib/types.ts';

const SEV: Record<AlertRow['severity'], { status: Status; label: string }> = {
  critical: { status: 'fail', label: 'Critical' },
  warning: { status: 'warn', label: 'Warning' },
  info: { status: 'info', label: 'Info' },
};

export function Alerts() {
  const { current } = useOrg();
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null);
  const load = async () => {
    if (!current) return;
    const { data } = await db().from('alerts').select('*').eq('org_id', current.id).order('created_at', { ascending: false }).limit(100);
    setAlerts((data ?? []) as AlertRow[]);
  };
  useEffect(() => {
    void load();
  }, [current?.id]);
  const markRead = async (ids: number[]) => {
    if (!ids.length) return;
    await db().from('alerts').update({ read_at: new Date().toISOString() }).in('id', ids);
    await load();
  };
  if (!alerts) return <Spinner />;
  const unread = alerts.filter((a) => !a.read_at);
  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <h1 className="text-3xl">Alerts</h1>
        {unread.length > 0 && (
          <Button variant="secondary" onClick={() => markRead(unread.map((a) => a.id))}>
            Mark all as read
          </Button>
        )}
      </div>
      {alerts.length === 0 ? (
        <EmptyState title="No alerts">We&apos;ll tell you here, and by email for critical issues, when a record changes, a blocklist lists you, or a new sender appears.</EmptyState>
      ) : (
        <ul className="divide-y divide-rule rounded-xl border border-rule bg-sheet">
          {alerts.map((a) => (
            <li key={a.id} className={`flex flex-col gap-2 px-5 py-4 sm:flex-row sm:items-start sm:justify-between ${a.read_at ? 'opacity-70' : ''}`}>
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge status={SEV[a.severity].status}>{SEV[a.severity].label}</Badge>
                  <span className="font-medium">{a.title}</span>
                </div>
                {a.body && <p className="whitespace-pre-line text-[15px] text-ink-soft break-all">{a.body}</p>}
                <p className="text-sm text-ink-faint">
                  {timeAgo(a.created_at)}
                  {a.domain_id && (
                    <>
                      {', '}
                      <Link className="underline" to={`/app/domains/${a.domain_id}`}>
                        open domain
                      </Link>
                    </>
                  )}
                </p>
              </div>
              {!a.read_at && (
                <button className="shrink-0 text-sm text-ink-soft underline hover:text-ink" onClick={() => markRead([a.id])}>
                  Mark as read
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
