# Maily Flex — Product Design (v1, 2026-11-08)

Builds on `claude/mailyflex-build-plan.md` and `claude/competitor-teardown.md`.

## 1. Repo layout (npm workspaces monorepo)

```
packages/core/          Pure TypeScript, no Node/Deno APIs. Runs in browser, Deno (edge functions) and Workers.
  src/dns.ts            DNS-over-HTTPS resolver (Cloudflare, Google fallback), injectable for tests
  src/spf.ts            parse, validate, 10-lookup + void-lookup counter, expand tree, flatten + chunk
  src/dkim.ts           parse key record, key-size estimate, selector discovery
  src/dmarc.ts          RFC 9989 parse/validate (np, psd, t; historic pct/rf/ri), tree-walk lookup, generator
  src/bimi.ts, mtasts.ts, tlsrpt.ts, mx.ts, blacklist.ts
  src/senders.ts        known-sender catalog; IP → PTR/ASN → service
  src/report.ts         DMARC aggregate (RFC 9990 / 7489) XML parse; gzip/zip unpack
  src/health.ts         full domain scan, 0–100 score, plain-English fix list
  src/generators.ts     SPF + DMARC record builders
  src/enforcement.ts    policy ladder + readiness checks
apps/web/               React + TS + Vite + Tailwind (Netlify)
supabase/migrations/    schema, RLS, functions, cron
supabase/functions/     Deno edge functions (import core via import map)
workers/mailyflex-edge/ Cloudflare Worker: MTA-STS policy hosting for custom hostnames
.github/workflows/ci.yml
```

## 2. Data model (Postgres, all tables RLS-enabled)

| Table | Key columns | Notes |
|---|---|---|
| `profiles` | id (= auth.users.id), email, full_name | auto-created by trigger on signup |
| `organizations` | id, name, plan, created_by | creator becomes owner (trigger) |
| `memberships` | org_id, user_id, role (`owner`/`admin`/`member`/`viewer`) | PK (org_id, user_id) |
| `invites` | id, org_id, email, role, token (hashed), expires_at, accepted_at | accepted via `accept_invite(token)` RPC |
| `domains` | id, org_id, name (unique), verification_token, verified_at, report_token, health_score, last_scan_at, hosted_dmarc/spf/mta_sts flags | `report_token` builds the RUA address `<token>@rua.mailyflex.com` |
| `domain_scans` | id, domain_id, score, result jsonb, records jsonb (raw values per record type), created_at | history; diff of `records` drives change alerts |
| `dmarc_policies` | domain_id PK, p, sp, np, adkim, aspf, t, extra_rua[], ruf[] | hosted DMARC config |
| `spf_configs` | domain_id PK, includes[], ip4[], ip6[], all_qualifier, flattened jsonb, flattened_at, lookup_count | hosted SPF |
| `mta_sts_configs` | domain_id PK, mode (none/testing/enforce), mx[], max_age, policy_id, tlsrpt_rua[] | hosted MTA-STS + TLS-RPT |
| `dmarc_reports` | id, domain_id, org_name, report_id, date_begin, date_end, policy jsonb | unique (domain_id, org_name, report_id) for idempotency |
| `dmarc_records` | id, report_id, domain_id, source_ip, count, disposition, dkim_aligned, spf_aligned, header_from, envelope_from, dkim jsonb, spf jsonb, sender_key, day | indexed (domain_id, day) |
| `ip_intel` | ip PK, ptr, asn, as_name, sender_key, updated_at | cache for sender identification |
| `alerts` | id, org_id, domain_id, kind, severity, title, body, created_at, read_at | |
| `alert_settings` | org_id PK, weekly_digest, email_on_critical, pass_rate_threshold | |
| `inbound_log` | id, resend_email_id unique, status, error, created_at | service-role only; debugging + idempotency |

**RLS:** helper `public.org_role(org_id)` (security definer) returns the caller's role. Read = any member; write config = owner/admin; members/invites managed by owner/admin; report tables are insert-only by service role. Views aggregate reports per day/sender with `security_invoker = true`.

**RPCs:** `create_organization(name)`, `accept_invite(token)`, `domain_daily_stats(domain_id, days)`, `domain_sender_stats(domain_id, days)`, `mta_sts_policy(host)` (anon-callable, returns only the public policy text used by the Worker).

## 3. Edge functions (Deno)

| Function | Auth | Purpose |
|---|---|---|
| `mta-sts-fetch` | anon | Fetch `https://mta-sts.<domain>/.well-known/mta-sts.txt` for the public checker (browser CORS blocks direct fetch). Fixed host pattern + path, 5 s timeout, 64 KB cap. |
| `domain-verify` | user JWT | Check `_mailyflex.<domain>` TXT = token, then mark verified and trigger first scan. |
| `domain-scan` | user JWT (one domain) or cron secret (all) | Run `scanDomain`, store scan, diff records → alerts, blacklist alerts. |
| `dmarc-inbound` | Svix signature (Resend) | `email.received` → list attachments → download → gunzip/unzip → parse XML → map recipient token → domain → upsert report + records → enrich IPs. |
| `dns-sync` | user JWT (admin) or cron secret | Render hosted DMARC/SPF/MTA-STS/TLS-RPT records and upsert them in the Cloudflare zone; re-flatten SPF; ensure MTA-STS custom hostname. |
| `invite` | user JWT (admin) | Create invite + send email via Resend. |
| `digest` | cron secret | Weekly digest + pass-rate-drop / new-sender alerts. |

**pg_cron** (via `pg_net` with secrets in Vault): scan all domains every 6 h; SPF re-flatten every 6 h (`dns-sync`); digest Mondays 08:00 UTC.

## 4. Hosted DNS design (Cloudflare zone `dns.mailyflex.com`)

Records are keyed on each domain's random `report_token` (not the domain name), so names never collide between customers and never exceed DNS length limits.

| Customer record | Points to | We publish |
|---|---|---|
| `_dmarc.example.com CNAME` | `<token>._d.dns.mailyflex.com` | TXT `v=DMARC1; p=…; rua=mailto:<token>@rua.mailyflex.com` |
| `example.com TXT` | `v=spf1 include:<token>._s.dns.mailyflex.com ~all` | flattened ip4/ip6 chain `<token>._s`, `<token>-1._s`, … (each ≤ 450 bytes, split into 255-byte strings) |
| `_mta-sts.example.com CNAME` | `<token>._m.dns.mailyflex.com` | TXT `v=STSv1; id=<policy_id>` |
| `mta-sts.example.com CNAME` | `sts.dns.mailyflex.com` (fallback origin) | custom hostname + Worker serves policy |
| `_smtp._tls.example.com CNAME` | `<token>._t.dns.mailyflex.com` | TXT `v=TLSRPTv1; rua=mailto:<token>@tls.mailyflex.com` |

External report authorization: wildcard `*._report._dmarc.rua.mailyflex.com TXT "v=DMARC1"`, so receivers accept our RUA address for any customer domain.

SPF flattening is macro-free (works with every receiver). Terms that can't be flattened safely (`exists`, macros, `ptr`) are kept verbatim. If any include fails to resolve during a refresh, the last good flattening stays published. Records are only published for verified domains.

## 5. Health score (0–100)

| Area | Weight | Full marks when |
|---|---|---|
| DMARC | 35 | valid record; p=reject (quarantine 25, none 12); rua set; no historic tags |
| SPF | 25 | single valid record, ≤10 lookups, ≤2 void, ends `-all`/`~all` |
| DKIM | 20 | ≥1 selector found, all keys ≥1024 bits (2048 preferred) |
| MX | 5 | MX present and resolvable (or explicit null MX) |
| MTA-STS + TLS-RPT | 10 | TXT + policy valid, mode enforce/testing; TLS-RPT present |
| BIMI | 5 | valid record (only counted when DMARC is enforcing) |

Blacklist listings subtract up to 20. Every deduction emits a fix item: `{severity, area, title, detail, fix: {type, host, value}}`, in plain English with copy-paste DNS.

## 6. Enforcement wizard

Ladder: `none` → `quarantine t=y` → `quarantine` → `reject t=y` → `reject`. A step is offered only when the last 14 days show: ≥ 98% DMARC-aligned pass rate across known senders, no unknown sender above 1% of volume, ≥ 7 days of reports, and SPF ≤ 10 lookups. Hosted DMARC applies the change instantly; otherwise the wizard shows the exact TXT record to paste.

## 7. Screens (routes)

Public: `/` landing · `/tools` hub · `/tools/domain` (all-in-one) · `/tools/spf` · `/tools/dkim` · `/tools/dmarc` · `/tools/bimi` · `/tools/mta-sts` · `/tools/tls-rpt` · `/tools/mx` · `/tools/blacklist` · `/tools/spf-generator` · `/tools/dmarc-generator` · `/login` · `/signup`

App: `/app` (domain list + scores) · `/app/new-org` · `/app/domains/new` (add + verify) · `/app/domains/:id` tabs **Overview** (score, fix list, records) · **Reports** (volume/pass over time) · **Senders** (identified services, alignment) · **Managed DNS** (hosted DMARC/SPF/MTA-STS setup + editors) · **Enforcement** (wizard) · `/app/alerts` · `/app/settings` (org, team, invites, alert settings) · `/invite/:token`

Free checkers run DNS queries from the browser via DoH (no backend load); only the MTA-STS policy fetch goes through the edge function.

## 8. Out of scope for v1 (later phases)

Payments, MSP/white-label, DNS-provider API integrations, RUF/failure reports, TLS-RPT report ingestion, BIMI logo hosting/VMC, SSO.
