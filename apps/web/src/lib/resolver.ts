import { CachingResolver, DohResolver, type PolicyFetcher, type Resolver } from '@mailyflex/core';
import { supabase } from './supabase.ts';

/** Fresh caching resolver per check so results are current but each check dedupes its own queries. */
export function newResolver(): Resolver {
  return new CachingResolver(new DohResolver());
}

/** Browsers can't fetch mta-sts.<domain> directly (CORS), so go through the edge function when available. */
export const browserPolicyFetcher: PolicyFetcher | null = supabase
  ? async (domain) => {
      const { data, error } = await supabase!.functions.invoke('mta-sts-fetch', { body: { domain } });
      if (error) return { ok: false, error: 'Policy fetch service unavailable' };
      return data as { ok: boolean; status?: number; body?: string; error?: string };
    }
  : null;
