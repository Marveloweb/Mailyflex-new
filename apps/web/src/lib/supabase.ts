import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { SUPABASE_ANON_KEY, SUPABASE_URL, backendConfigured } from './config.ts';

export const supabase: SupabaseClient | null = backendConfigured
  ? createClient(SUPABASE_URL!, SUPABASE_ANON_KEY!, { auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true } })
  : null;

export function db(): SupabaseClient {
  if (!supabase) throw new Error('The Maily Flex backend is not configured. Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.');
  return supabase;
}

/** Call an edge function and surface its { error } message. */
export async function callFunction<T>(name: string, body: unknown): Promise<T> {
  const { data, error } = await db().functions.invoke(name, { body: body as Record<string, unknown> });
  if (error) {
    let message = error.message;
    const ctx = (error as { context?: Response }).context;
    if (ctx && typeof ctx.json === 'function') {
      try {
        const j = await ctx.json();
        if (j?.error) message = j.error;
      } catch {
        /* keep default */
      }
    }
    throw new Error(message);
  }
  return data as T;
}

export function errorMessage(e: unknown): string {
  if (e instanceof Error) return e.message;
  if (e && typeof e === 'object' && 'message' in e) return String((e as { message: unknown }).message);
  return String(e);
}
