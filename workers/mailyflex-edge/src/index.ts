/**
 * Serves https://mta-sts.<customer-domain>/.well-known/mta-sts.txt for domains with hosted MTA-STS.
 * Customers CNAME mta-sts.<domain> to the Cloudflare for SaaS fallback origin; Cloudflare issues the
 * certificate for the custom hostname and routes the request here. The policy text comes from the
 * Supabase RPC `mta_sts_policy`, which only answers for verified domains with hosting turned on.
 */
export interface Env {
  SUPABASE_URL: string;
  SUPABASE_ANON_KEY: string;
}

const POLICY_PATH = '/.well-known/mta-sts.txt';
const CACHE_SECONDS = 300;

function text(body: string, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(body, { status, headers: { 'content-type': 'text/plain; charset=utf-8', 'x-content-type-options': 'nosniff', ...extra } });
}

export async function fetchPolicy(host: string, env: Env, fetchImpl: typeof fetch = fetch): Promise<string | null> {
  const res = await fetchImpl(`${env.SUPABASE_URL.replace(/\/$/, '')}/rest/v1/rpc/mta_sts_policy`, {
    method: 'POST',
    headers: { apikey: env.SUPABASE_ANON_KEY, authorization: `Bearer ${env.SUPABASE_ANON_KEY}`, 'content-type': 'application/json' },
    body: JSON.stringify({ p_host: host }),
  });
  if (!res.ok) throw new Error(`policy lookup failed: HTTP ${res.status}`);
  const value = (await res.json()) as string | null;
  return typeof value === 'string' && value.startsWith('version: STSv1') ? value : null;
}

export async function handle(request: Request, env: Env, deps: { fetchImpl?: typeof fetch; cache?: Cache } = {}): Promise<Response> {
  const url = new URL(request.url);
  const host = url.hostname.toLowerCase();
  if (url.pathname === '/health') return text('ok');
  if (request.method !== 'GET' && request.method !== 'HEAD') return text('Method not allowed', 405, { allow: 'GET, HEAD' });
  if (!host.startsWith('mta-sts.') || url.pathname !== POLICY_PATH) return text('Not found', 404);
  if (url.protocol !== 'https:') return text('MTA-STS policies are only served over HTTPS', 403);

  const cacheKey = new Request(`https://${host}${POLICY_PATH}`);
  const cached = await deps.cache?.match(cacheKey);
  if (cached) return cached;

  let policy: string | null;
  try {
    policy = await fetchPolicy(host, env, deps.fetchImpl);
  } catch (e) {
    console.error(e);
    return text('Policy temporarily unavailable', 503, { 'retry-after': '60' });
  }
  const response = policy
    ? text(policy, 200, { 'cache-control': `public, max-age=${CACHE_SECONDS}` })
    : text('No MTA-STS policy is hosted for this domain', 404, { 'cache-control': 'public, max-age=60' });
  await deps.cache?.put(cacheKey, response.clone());
  return response;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    void ctx;
    return handle(request, env, { cache: caches.default });
  },
} satisfies ExportedHandler<Env>;
