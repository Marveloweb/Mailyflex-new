// Public: fetch https://mta-sts.<domain>/.well-known/mta-sts.txt for the browser-based checker (CORS).
import { DohResolver, directPolicyFetcher, isValidDomain, normalizeDomain } from '@mailyflex/core';
import { handler, HttpError, json, readJson } from '../_shared/http.ts';

const PRIVATE_V4 = [/^0\./, /^10\./, /^127\./, /^169\.254\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, /^22[4-9]\./, /^2[3-5]\d\./];

function isPublicAddress(ip: string): boolean {
  if (ip.includes(':')) {
    const l = ip.toLowerCase();
    return !(l === '::1' || l.startsWith('fc') || l.startsWith('fd') || l.startsWith('fe80') || l.startsWith('::ffff:') || l === '::');
  }
  return !PRIVATE_V4.some((re) => re.test(ip));
}

Deno.serve(
  handler(async (req) => {
    const url = new URL(req.url);
    const body = req.method === 'POST' ? await readJson<{ domain?: string }>(req) : {};
    const domain = normalizeDomain(body.domain ?? url.searchParams.get('domain') ?? '');
    if (!isValidDomain(domain)) throw new HttpError(400, 'Enter a valid domain name');
    const host = `mta-sts.${domain}`;
    // Refuse hosts that resolve to private / internal addresses (SSRF guard).
    const resolver = new DohResolver();
    const [a, aaaa] = await Promise.all([resolver.query(host, 'A'), resolver.query(host, 'AAAA')]);
    const ips = [...a.answers, ...aaaa.answers].map((x) => x.data);
    if (ips.length === 0) return json(req, { ok: false, error: `${host} does not resolve` });
    if (!ips.every(isPublicAddress)) return json(req, { ok: false, error: `${host} resolves to a private address` });
    const r = await directPolicyFetcher(domain);
    return json(req, r, 200, { 'Cache-Control': 'public, max-age=60' });
  }),
);
