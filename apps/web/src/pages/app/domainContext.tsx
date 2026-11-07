import { createContext, useContext } from 'react';
import type { DomainRow, ScanRow } from '../../lib/types.ts';
import type { Role } from '../../lib/org.tsx';

export interface DomainCtx {
  domain: DomainRow;
  scan: ScanRow | null;
  role: Role | undefined;
  reload: () => Promise<void>;
}

export const DomainContext = createContext<DomainCtx | null>(null);

export function useDomain(): DomainCtx {
  const ctx = useContext(DomainContext);
  if (!ctx) throw new Error('useDomain outside DomainContext');
  return ctx;
}
