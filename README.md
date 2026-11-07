# Maily Flex

Maily Flex manages the DNS records that decide whether a business's email reaches the inbox: SPF, DKIM, DMARC, BIMI, MTA-STS and TLS-RPT. It checks a domain, explains what to fix in plain English, reads the daily DMARC reports from Gmail, Outlook and Yahoo to show who sends as the domain, and can host the records itself so policies change without touching the customer's DNS again.

- Free public checkers and generators (no account): domain health, SPF with nested lookup counting, DKIM selector discovery, DMARC per RFC 9989, BIMI, MTA-STS, TLS-RPT, MX, DNS blocklists.
- Accounts with organizations, roles (viewer, member, admin, owner) and email invites.
- Domain verification by TXT record, 0–100 health score, prioritized fix list with copy-paste records.
- DMARC aggregate report ingestion (Resend Inbound), daily volume and pass-rate charts, sender identification (Google Workspace, Microsoft 365, SendGrid, Mailchimp and more, by DKIM/SPF domain, PTR and ASN).
- Hosted DMARC, hosted SPF with automatic macro-free flattening under the 10-lookup limit, hosted MTA-STS policy and TLS-RPT, all via one-time CNAME/TXT delegation.
- Enforcement wizard from `p=none` to `p=reject`, gated on 14 days of real report data.
- Alerts for DNS record changes, blocklist listings, pass-rate drops and new senders, plus a weekly digest email.

Product research and design: [`docs/competitor-teardown.md`](docs/competitor-teardown.md), [`docs/product-design.md`](docs/product-design.md).

## Architecture

```
Browser (React, Netlify) ──DoH──▶ Cloudflare / Google DNS        (free checkers run client-side)
        │
        ├──▶ Supabase Postgres (RLS)  ◀── pg_cron ──▶ Edge Functions (Deno)
        │                                              ├─ domain-scan / domain-verify
        └──▶ Edge Functions ───────────────────────────├─ dmarc-inbound  ◀── Resend Inbound webhook
                                                       ├─ dns-sync ──▶ Cloudflare DNS API (zone dns.mailyflex.com)
                                                       ├─ invite / digest ──▶ Resend email
                                                       └─ mta-sts-fetch
Cloudflare Worker (mailyflex-edge) serves https://mta-sts.<customer>/.well-known/mta-sts.txt
```

| Path | What it is |
|---|---|
| `packages/core` | Pure TypeScript email-auth engine shared by browser, Deno and Workers: DoH resolver, SPF/DKIM/DMARC/MTA-STS/TLS-RPT/BIMI analysis, blocklists, sender catalog, aggregate-report parser, health score, hosted-record rendering. |
| `apps/web` | React 19 + Vite + Tailwind 4 web app (public tools and dashboard). |
| `supabase/migrations` | Schema, row-level security, RPCs, pg_cron jobs. |
| `supabase/functions` | Edge functions. `_shared/core` is a generated copy of `packages/core/src` (`npm run sync-core`). |
| `workers/mailyflex-edge` | Cloudflare Worker for hosted MTA-STS policies. |
| `supabase/tests`, `scripts/test-db.sh` | Database tests (tenant isolation, column privileges, invites, owner safety, ingestion). |
| `tests/e2e` | Browser click-through against a local Supabase stack (Playwright, Python). |

## Local development

Requirements: Node 22, Deno 2, Docker (for the local Supabase stack), the [Supabase CLI](https://supabase.com/docs/guides/local-development).

```bash
npm install
supabase start                      # Postgres, Auth, REST, Edge Runtime; applies migrations
cp supabase/functions/.env.example supabase/functions/.env   # fill CRON_SECRET at least
supabase functions serve --env-file supabase/functions/.env

cp apps/web/.env.example apps/web/.env.local
# set VITE_SUPABASE_URL=http://127.0.0.1:54321 and VITE_SUPABASE_ANON_KEY from `supabase status`
npm run dev                         # http://localhost:5173
```

The public tools work without a backend: if `VITE_SUPABASE_URL` is unset, the dashboard routes show a setup notice and everything under `/tools` still runs.

After editing `packages/core/src`, run `npm run sync-core` so the edge functions get the change (CI fails if the copy is stale).

## Tests

```bash
npm run typecheck        # core, web, worker
npm test                 # core (Vitest) + worker
npm run test:db          # migrations + RLS tests on a throwaway Postgres (needs initdb/pg_ctl, or DATABASE_URL to an empty DB)
npm run check:functions  # deno check of every edge function
npm run test:functions   # Deno tests (report ingestion pipeline, webhook signatures)
LIVE_DNS=1 npx vitest run --root packages/core test/health.test.ts   # optional: real DNS scans
```

End-to-end: with the local stack running, the web app built against it and served on port 4173 (`npm run build -w @mailyflex/web && npx vite preview --port 4173` in `apps/web`), run `python3 tests/e2e/run.py`. It signs up, creates an organization, adds and verifies a domain, seeds DMARC data, runs a real scan, walks every tab, turns on hosted DMARC, invites a teammate and accepts the invite in a second browser.

## Deploying

### 1. Supabase

1. Create a project, then `supabase link --project-ref <ref>` and `supabase db push`.
2. Store two Vault secrets so pg_cron can call the functions (SQL editor):
   ```sql
   select vault.create_secret('https://<ref>.supabase.co', 'project_url');
   select vault.create_secret('<long random string>', 'cron_secret');
   ```
3. Set function secrets (same `CRON_SECRET` value as the Vault secret): `supabase secrets set --env-file supabase/functions/.env`.
4. Deploy functions: `supabase functions deploy`. All use `verify_jwt = false` in `supabase/config.toml` because each checks its own auth (user JWT, cron secret or webhook signature).
5. Auth → URL configuration: site URL `https://app.mailyflex.com`, and add it to redirect URLs. Use Resend as the custom SMTP provider so sign-up emails come from your domain.

### 2. Resend

1. Verify a sending domain (for `MAIL_FROM`) and create an API key → `RESEND_API_KEY`.
2. Add an inbound (receiving) domain for reports, e.g. `rua.mailyflex.com` (MX to Resend). Use a subdomain so normal mail is unaffected.
3. Create a webhook for `email.received` pointing to `https://<ref>.supabase.co/functions/v1/dmarc-inbound`; its signing secret → `RESEND_WEBHOOK_SECRET`.
4. Authorise reports for any customer domain (RFC 9990 external destination check) in the `mailyflex.com` zone:
   `*._report._dmarc.rua.mailyflex.com  TXT  "v=DMARC1"`

### 3. Cloudflare (hosted records)

1. Add the zone used for hosted records (e.g. `dns.mailyflex.com`, as its own zone or delegated subdomain) and note its zone ID → `CLOUDFLARE_ZONE_ID`.
2. Create an API token with *Zone → DNS → Edit* and *Zone → SSL and Certificates → Edit* on that zone → `CLOUDFLARE_API_TOKEN`.
3. SSL/TLS → Custom Hostnames: enable Cloudflare for SaaS and set the fallback origin to `sts.dns.mailyflex.com` (a proxied `AAAA 100::` record is fine).
4. Deploy the worker: in `workers/mailyflex-edge`, set `SUPABASE_URL` in `wrangler.toml`, then `npx wrangler secret put SUPABASE_ANON_KEY` and `npm run deploy`. Add a route `*/*` on the zone to the worker.

### 4. Netlify

Create a site from this repository. `netlify.toml` builds `apps/web`. Set `VITE_SUPABASE_URL`, `VITE_SUPABASE_ANON_KEY` and, if you changed them, the `VITE_HOSTED_DNS_ZONE` / `VITE_RUA_DOMAIN` / `VITE_TLSRPT_DOMAIN` / `VITE_MTA_STS_TARGET` variables (they must match the function secrets).

## How hosted records work

Each domain has a random token. Customers add, once:

| Feature | Customer record | Points to |
|---|---|---|
| DMARC | `_dmarc.example.com CNAME` | `<token>._d.dns.mailyflex.com` (TXT with policy and our report address) |
| SPF | `example.com TXT v=spf1 include:<token>._s.dns.mailyflex.com ~all` | flattened `ip4`/`ip6` chain `<token>._s`, `<token>-1._s`, … (≤ 450 bytes each, refreshed every 6 h; last good copy kept if DNS lookups fail) |
| MTA-STS | `_mta-sts.example.com CNAME`, `mta-sts.example.com CNAME` | `<token>._m.dns.mailyflex.com` (TXT `v=STSv1; id=…`), `sts.dns.mailyflex.com` (Worker) |
| TLS-RPT | `_smtp._tls.example.com CNAME` | `<token>._t.dns.mailyflex.com` |

Hosted records are only published for verified domains. Ownership verification is a TXT record at `_mailyflex.example.com`.

## Standards

SPF RFC 7208 · DKIM RFC 6376 · DMARC RFC 9989 / 9990 / 9991 (May 2026; `np`, `psd`, `t` supported, `pct`/`rf`/`ri` flagged as historic) · MTA-STS RFC 8461 · TLS-RPT RFC 8460 · BIMI (draft) · Null MX RFC 7505.

## Not in v1

Payments, MSP/white-label, direct DNS-provider integrations (GoDaddy, Route 53), RUF failure reports, TLS-RPT report ingestion, BIMI logo hosting, SSO.
