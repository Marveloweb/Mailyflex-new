import { Link, NavLink, Outlet } from 'react-router';
import { Logo } from './Logo.tsx';
import { useAuth } from '../lib/auth.tsx';

export function PublicLayout() {
  const { session } = useAuth();
  const nav = 'rounded-md px-3 py-1.5 text-[15px] text-ink-soft hover:text-ink';
  return (
    <div className="flex min-h-screen flex-col">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:rounded focus:bg-sheet focus:px-3 focus:py-2">
        Skip to content
      </a>
      <header className="border-b border-rule bg-paper/90 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-5 py-3">
          <Link to="/" aria-label="Maily Flex home" className="shrink-0 whitespace-nowrap">
            <Logo />
          </Link>
          <nav className="flex items-center gap-1 whitespace-nowrap">
            <NavLink to="/tools" className={({ isActive }) => `${nav} hidden sm:inline ${isActive ? 'text-ink' : ''}`}>
              Free tools
            </NavLink>
            {session ? (
              <Link to="/app" className="ml-2 rounded-lg bg-ink px-4 py-1.5 text-[15px] font-medium text-white hover:bg-[#1f3157]">
                Open dashboard
              </Link>
            ) : (
              <>
                <NavLink to="/login" className={nav}>
                  Sign in
                </NavLink>
                <Link to="/signup" className="ml-2 rounded-lg bg-ink px-4 py-1.5 text-[15px] font-medium text-white hover:bg-[#1f3157]">
                  Start free
                </Link>
              </>
            )}
          </nav>
        </div>
      </header>
      <main id="main" className="flex-1">
        <Outlet />
      </main>
      <footer className="border-t border-rule">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-4 px-5 py-8 text-sm text-ink-soft">
          <Logo className="text-ink" />
          <p>Checks follow RFC 7208 (SPF), 6376 (DKIM), 9989 (DMARC), 8461 (MTA-STS) and 8460 (TLS-RPT).</p>
        </div>
      </footer>
    </div>
  );
}
