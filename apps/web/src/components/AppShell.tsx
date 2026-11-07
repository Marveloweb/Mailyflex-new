import { useEffect, useState } from 'react';
import { Link, NavLink, Navigate, Outlet, useLocation, useNavigate } from 'react-router';
import { Logo } from './Logo.tsx';
import { Spinner } from './ui.tsx';
import { useAuth } from '../lib/auth.tsx';
import { useOrg } from '../lib/org.tsx';
import { backendConfigured } from '../lib/config.ts';
import { supabase } from '../lib/supabase.ts';

function useUnreadAlerts(orgId: string | undefined) {
  const [count, setCount] = useState(0);
  const { pathname } = useLocation();
  useEffect(() => {
    if (!supabase || !orgId) return;
    supabase
      .from('alerts')
      .select('id', { count: 'exact', head: true })
      .eq('org_id', orgId)
      .is('read_at', null)
      .then(({ count: c }) => setCount(c ?? 0));
  }, [orgId, pathname]);
  return count;
}

export function AppShell() {
  const { session, loading } = useAuth();
  const { orgs, current, loading: orgLoading, select } = useOrg();
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const unread = useUnreadAlerts(current?.id);
  const [menuOpen, setMenuOpen] = useState(false);

  if (!backendConfigured) return <Navigate to="/setup-required" replace />;
  if (loading || (session && orgLoading)) {
    return (
      <div className="flex min-h-screen items-center justify-center text-ink-soft">
        <Spinner />
      </div>
    );
  }
  if (!session) return <Navigate to={`/login?next=${encodeURIComponent(pathname)}`} replace />;
  if (!orgs.length && pathname !== '/app/new-org') return <Navigate to="/app/new-org" replace />;

  const link = ({ isActive }: { isActive: boolean }) =>
    `flex items-center justify-between rounded-lg px-3 py-2 text-[15px] ${isActive ? 'bg-sheet font-medium text-ink shadow-[inset_3px_0_0_var(--color-airmail-red)]' : 'text-ink-soft hover:text-ink'}`;

  const sidebar = (
    <div className="flex h-full flex-col gap-6 p-4">
      <Link to="/app" onClick={() => setMenuOpen(false)}>
        <Logo />
      </Link>
      {orgs.length > 0 && (
        <div>
          <label htmlFor="org" className="mb-1 block text-sm text-ink-soft">
            Organization
          </label>
          <select
            id="org"
            value={current?.id ?? ''}
            onChange={(e) => {
              if (e.target.value === '__new') navigate('/app/new-org');
              else {
                select(e.target.value);
                navigate('/app');
              }
            }}
            className="w-full rounded-lg border border-rule bg-sheet px-2 py-1.5 text-[15px]"
          >
            {orgs.map((o) => (
              <option key={o.id} value={o.id}>
                {o.name}
              </option>
            ))}
            <option value="__new">New organization…</option>
          </select>
        </div>
      )}
      <nav className="flex flex-col gap-1" onClick={() => setMenuOpen(false)}>
        <NavLink to="/app" end className={link}>
          Domains
        </NavLink>
        <NavLink to="/app/alerts" className={link}>
          Alerts
          {unread > 0 && <span className="rounded-full bg-airmail-red px-2 text-[12px] font-semibold text-white">{unread}</span>}
        </NavLink>
        <NavLink to="/app/settings" className={link}>
          Settings
        </NavLink>
        <NavLink to="/tools" className={link}>
          Free tools
        </NavLink>
      </nav>
      <div className="mt-auto space-y-2 border-t border-rule pt-4 text-sm">
        <p className="truncate text-ink-soft" title={session.user.email}>
          {session.user.email}
        </p>
        <button
          className="text-ink-soft underline hover:text-ink"
          onClick={async () => {
            await supabase?.auth.signOut();
            navigate('/');
          }}
        >
          Sign out
        </button>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen md:grid md:grid-cols-[15rem_1fr]">
      <aside className="hidden border-r border-rule bg-paper md:block">{sidebar}</aside>
      <div className="flex items-center justify-between border-b border-rule px-4 py-3 md:hidden">
        <Logo />
        <button className="rounded-md border border-rule px-3 py-1 text-sm" aria-expanded={menuOpen} onClick={() => setMenuOpen((v) => !v)}>
          Menu
        </button>
      </div>
      {menuOpen && <div className="border-b border-rule bg-paper md:hidden">{sidebar}</div>}
      <main id="main" className="min-w-0 bg-[#f9fafc]">
        <div className="mx-auto max-w-5xl px-5 py-8 md:px-10">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
