import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { supabase } from './supabase.ts';
import { useAuth } from './auth.tsx';

export type Role = 'viewer' | 'member' | 'admin' | 'owner';
export interface Org {
  id: string;
  name: string;
  role: Role;
}

interface OrgState {
  orgs: Org[];
  current: Org | null;
  loading: boolean;
  select: (id: string) => void;
  reload: () => Promise<void>;
}

const OrgContext = createContext<OrgState>({ orgs: [], current: null, loading: true, select: () => {}, reload: async () => {} });
const KEY = 'mailyflex.org';
const RANK: Record<Role, number> = { viewer: 0, member: 1, admin: 2, owner: 3 };

export function atLeast(role: Role | undefined, min: Role): boolean {
  return !!role && RANK[role] >= RANK[min];
}

function readSaved(): string | null {
  try {
    return localStorage.getItem(KEY);
  } catch {
    return null;
  }
}

export function OrgProvider({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [currentId, setCurrentId] = useState<string | null>(readSaved());
  const [fetching, setFetching] = useState(false);
  // Which user the current org list belongs to. Until it matches the session, we are still loading;
  // otherwise there is a render where a signed-in user appears to have no organizations.
  const [loadedFor, setLoadedFor] = useState<string | null>(null);
  const userId = session?.user.id ?? null;

  const reload = useCallback(async () => {
    if (!supabase || !session) {
      setOrgs([]);
      setLoadedFor(null);
      return;
    }
    setFetching(true);
    const { data } = await supabase
      .from('memberships')
      .select('role, organizations(id, name)')
      .eq('user_id', session.user.id);
    const list = (data ?? [])
      .map((m: { role: Role; organizations: { id: string; name: string } | { id: string; name: string }[] | null }) => {
        const o = Array.isArray(m.organizations) ? m.organizations[0] : m.organizations;
        return o ? { id: o.id, name: o.name, role: m.role } : null;
      })
      .filter((o): o is Org => !!o)
      .sort((a, b) => a.name.localeCompare(b.name));
    setOrgs(list);
    setLoadedFor(session.user.id);
    setFetching(false);
  }, [session]);
  // Only the first load for a user blocks the UI; later reloads refresh in place.
  const loading = userId !== null && loadedFor !== userId;
  void fetching;

  useEffect(() => {
    void reload();
  }, [reload]);

  const select = (id: string) => {
    setCurrentId(id);
    try {
      localStorage.setItem(KEY, id);
    } catch {
      /* private mode */
    }
  };
  const current = orgs.find((o) => o.id === currentId) ?? orgs[0] ?? null;
  return <OrgContext.Provider value={{ orgs, current, loading, select, reload }}>{children}</OrgContext.Provider>;
}

export const useOrg = () => useContext(OrgContext);
