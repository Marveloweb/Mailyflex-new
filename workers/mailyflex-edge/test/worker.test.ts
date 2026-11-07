import { describe, expect, it } from 'vitest';
import { handle, type Env } from '../src/index.ts';

const env: Env = { SUPABASE_URL: 'https://proj.supabase.co/', SUPABASE_ANON_KEY: 'anon' };
const POLICY = 'version: STSv1\r\nmode: enforce\r\nmx: mx1.acme.com\r\nmax_age: 604800\r\n';

function fakeFetch(answer: unknown, status = 200) {
  const calls: { url: string; body: string }[] = [];
  const fn = (async (url: string, init: RequestInit) => {
    calls.push({ url: String(url), body: String(init.body) });
    return new Response(JSON.stringify(answer), { status });
  }) as unknown as typeof fetch;
  return { fn, calls };
}

class MemCache {
  store = new Map<string, Response>();
  async match(req: Request) {
    return this.store.get(req.url)?.clone();
  }
  async put(req: Request, res: Response) {
    this.store.set(req.url, res);
  }
}

describe('mta-sts worker', () => {
  it('serves the policy for a hosted domain and caches it', async () => {
    const f = fakeFetch(POLICY);
    const cache = new MemCache() as unknown as Cache;
    const res = await handle(new Request('https://MTA-STS.acme.com/.well-known/mta-sts.txt'), env, { fetchImpl: f.fn, cache });
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toBe('text/plain; charset=utf-8');
    expect(await res.text()).toBe(POLICY);
    expect(f.calls[0]).toEqual({ url: 'https://proj.supabase.co/rest/v1/rpc/mta_sts_policy', body: '{"p_host":"mta-sts.acme.com"}' });
    const again = await handle(new Request('https://mta-sts.acme.com/.well-known/mta-sts.txt'), env, { fetchImpl: f.fn, cache });
    expect(await again.text()).toBe(POLICY);
    expect(f.calls).toHaveLength(1);
  });

  it('404s for unknown domains and other paths', async () => {
    expect((await handle(new Request('https://mta-sts.nope.com/.well-known/mta-sts.txt'), env, { fetchImpl: fakeFetch(null).fn })).status).toBe(404);
    expect((await handle(new Request('https://mta-sts.acme.com/'), env, { fetchImpl: fakeFetch(POLICY).fn })).status).toBe(404);
    expect((await handle(new Request('https://www.acme.com/.well-known/mta-sts.txt'), env, { fetchImpl: fakeFetch(POLICY).fn })).status).toBe(404);
  });

  it('refuses plain HTTP and non-GET, and 503s on backend failure', async () => {
    expect((await handle(new Request('http://mta-sts.acme.com/.well-known/mta-sts.txt'), env, { fetchImpl: fakeFetch(POLICY).fn })).status).toBe(403);
    expect((await handle(new Request('https://mta-sts.acme.com/.well-known/mta-sts.txt', { method: 'POST' }), env)).status).toBe(405);
    expect((await handle(new Request('https://mta-sts.acme.com/.well-known/mta-sts.txt'), env, { fetchImpl: fakeFetch({ message: 'x' }, 500).fn })).status).toBe(503);
    expect((await handle(new Request('https://sts.dns.mailyflex.com/health'), env)).status).toBe(200);
  });
});
