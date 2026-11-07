import { createClient, type SupabaseClient, type User } from '@supabase/supabase-js';
import { env, optionalEnv } from './env.ts';
import { HttpError } from './http.ts';

const url = () => env('SUPABASE_URL');
const serviceKey = () => optionalEnv('SUPABASE_SERVICE_ROLE_KEY') ?? env('SUPABASE_SECRET_KEY');
const anonKey = () => optionalEnv('SUPABASE_ANON_KEY') ?? env('SUPABASE_PUBLISHABLE_KEY');

/** Service-role client: bypasses RLS. Only use after authorising the caller. */
export function serviceClient(): SupabaseClient {
  return createClient(url(), serviceKey(), { auth: { persistSession: false, autoRefreshToken: false } });
}

/** Client acting as the calling user (RLS applies). */
export function userClient(req: Request): SupabaseClient {
  const authorization = req.headers.get('authorization') ?? '';
  return createClient(url(), anonKey(), {
    global: { headers: { Authorization: authorization } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

export async function requireUser(req: Request): Promise<{ user: User; client: SupabaseClient }> {
  const token = (req.headers.get('authorization') ?? '').replace(/^Bearer\s+/i, '');
  if (!token) throw new HttpError(401, 'Sign in required');
  const client = userClient(req);
  const { data, error } = await client.auth.getUser(token);
  if (error || !data.user) throw new HttpError(401, 'Invalid or expired session');
  return { user: data.user, client };
}

/** Constant-time comparison for shared secrets. */
export function safeEqual(a: string, b: string): boolean {
  const ea = new TextEncoder().encode(a);
  const eb = new TextEncoder().encode(b);
  if (ea.length !== eb.length) return false;
  let diff = 0;
  for (let i = 0; i < ea.length; i++) diff |= ea[i]! ^ eb[i]!;
  return diff === 0;
}

/**
 * True when the request carries the scheduler's shared secret. Uses the CRON_SECRET env var when set
 * (local development); otherwise checks it against the Vault secret "cron_secret" in the database,
 * which is the same value pg_cron sends.
 */
export async function isCron(req: Request): Promise<boolean> {
  const given = req.headers.get('x-cron-secret');
  if (!given || given.length > 256) return false;
  const secret = optionalEnv('CRON_SECRET');
  if (secret) return safeEqual(secret, given);
  const { data, error } = await serviceClient().rpc('check_cron_secret', { p_secret: given });
  return !error && data === true;
}

/** Domain row, visible to the caller only if RLS allows; enforces a minimum role. */
export async function requireDomainRole(
  req: Request,
  domainId: string,
  minRole: 'viewer' | 'member' | 'admin' | 'owner',
): Promise<{ user: User; domain: DomainRow }> {
  const { user, client } = await requireUser(req);
  const { data: domain } = await client.from('domains').select('*').eq('id', domainId).maybeSingle<DomainRow>();
  if (!domain) throw new HttpError(404, 'Domain not found');
  const { data: ok } = await client.rpc('has_org_role', { p_org: domain.org_id, p_min: minRole });
  if (!ok) throw new HttpError(403, `You need the ${minRole} role for this`);
  return { user, domain };
}

export interface DomainRow {
  id: string;
  org_id: string;
  name: string;
  verification_token: string;
  verified_at: string | null;
  report_token: string;
  health_score: number | null;
  grade: string | null;
  last_scan_at: string | null;
  dkim_selectors: string[];
  hosted_dmarc: boolean;
  hosted_spf: boolean;
  hosted_mta_sts: boolean;
  created_at: string;
}
