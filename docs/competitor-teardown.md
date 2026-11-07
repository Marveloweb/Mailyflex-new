# Maily Flex — Competitor Teardown (2026-11-08)

Feature-level teardown from public sources only (product pages, pricing pages, docs, third-party reviews). No competitor code, design or branding is used.

## 1. Summary

The market has three layers:

1. **Free diagnostics** (MxToolbox, every vendor's free tools): one-off lookups, used for top-of-funnel lead generation.
2. **DMARC reporting** (dmarcian, Valimail Monitor, Cloudflare DMARC Management): ingest aggregate reports and show who sends as your domain.
3. **Hosted/managed records** (EasyDMARC, Valimail Enforce, PowerDMARC, Red Sift OnDMARC): customer delegates DNS once via CNAME/include, and the vendor manages DMARC policy, SPF (beating the 10-lookup limit), DKIM, BIMI and MTA-STS after that.

Layer 3 is where money and lock-in sit. Maily Flex v1 covers all three layers at SMB-friendly, published prices.

## 2. Competitor by competitor

### EasyDMARC (primary)
- **Free tools:** large hub: DMARC/SPF/DKIM/BIMI checkers and generators, SPF "raw" checker, domain scanner with risk level.
- **Managed:** Managed DMARC via a single CNAME (one-click p=none → p=reject), EasySPF (dynamic SPF flattening), Managed DKIM, Managed BIMI (hosts SVG logo, VMC validation), Managed MTA-STS + TLS-RPT.
- **Reports:** RUA, RUF (failure), TLS reports, BIMI reporting, email vendor identification, reputation/blacklist monitoring, alerting.
- **Platform:** DNS integrations (Cloudflare, GoDaddy, Route 53, Google Cloud DNS, Azure, Namecheap, Gandi), SIEM (Sentinel, Splunk), API, MCP, AI agent, SSO/2FA/audit logs, MSP multi-tenant program.
- **Pricing:** free tier (1 domain, ~14-day history); paid from ~$35/mo; enterprise custom; data history 3 months → 3 years by tier.
- **Weak spots (reviews):** perceived price at scale; some newer add-ons feel thin.

### dmarcian (primary)
- Founded 2012 by a DMARC spec co-author; education-heavy brand.
- **Free tools:** DMARC Domain Checker, DMARC Inspector, Record Wizard, SPF Surveyor, DKIM Inspector/Validator, BIMI tools, "XML to Human" converter.
- **Platform:** enriched sources view, automatic subdomain detection, TLS reporting on all tiers (unique TLS-RPT address per account), BIMI inspector/builder, 2FA; user access controls on higher tiers; regional data hosting (Americas, EU, APAC, Canada, Australia, Japan).
- **Gap:** no MTA-STS hosting publicly documented; mostly *reporting + guidance*, little hosted-record automation.
- **Pricing:** Personal free (2 domains, 1 user, 1,250 msgs/mo, 1-month history); Basic ~$20–25/mo; Plus; Enterprise several hundred/mo; priced on domains, message volume, users, history.

### Valimail (primary)
- **Monitor (free):** visibility only; explicitly no policy or SPF/DKIM management.
- **Enforce (paid):** sender catalog / identification, one-click sender authorization, hosted DMARC, hosted DKIM, **Instant SPF** (patented SPF-macro approach; generates per-query SPF answers), BIMI, alerts, SIEM/M365/Workspace integrations, FedRAMP.
- **Pricing:** Enforce Starter ~$5,000/yr; Premium/Enterprise custom. Not SMB-friendly.
- **Notes:** strong sender intelligence; macro-based SPF can have compatibility issues with some legacy receivers (competitors market against this).

### PowerDMARC (secondary)
- Full stack: hosted DMARC, PowerSPF (hosted SPF, macros + flattening), hosted DKIM (enterprise), BIMI, MTA-STS, TLS-RPT, threat intel, encrypted forensic reports, MSP focus.
- Already ships RFC 9989/9990/9991 support (np/psd/t parsing, RFC 9990 aggregate ingestion).
- **Pricing:** free plan; paid from ~$8/mo; hosted SPF often bundled/quote-based.

### Red Sift OnDMARC (secondary)
- **Dynamic DMARC:** "smart" records for SPF, DKIM, DMARC, BIMI, managed in-app after a one-time DNS change.
- **Dynamic SPF:** flatten-and-compact, **no macros** (marketed as compatible with all receivers); runs on HA infra and keeps serving if the app is down; IP-range optimisation.
- Investigation tools, permissions without DNS access, sender identification, 14-day trial. Claims 6–8 weeks to enforcement.

### Cloudflare DMARC Management (secondary)
- Free for every Cloudflare customer; aggregate report processing, record analysis, SPF audit.
- Limited to Cloudflare-hosted zones; no hosted SPF flattening, no MTA-STS hosting; no dedicated DMARC data API. Support is mostly docs/community.

### MxToolbox (secondary)
- **SuperTool:** the default free lookup (MX, A, SPF, DKIM, DMARC, TXT, PTR, SMTP test, blacklist across 100+ RBLs). Command-driven; assumes expertise, no guided fix flow.
- **Delivery Center:** $129/mo (5 domains, 500K msgs, inbox placement, DMARC reporting, adaptive blacklist monitoring, mail-flow monitoring); **Plus** $399/mo adds SPF flattening and impersonation protection. Free plan: 1 weekly blacklist monitor, top-30 lists.

## 3. Feature matrix (v1 relevant)

| Capability | EasyDMARC | dmarcian | Valimail | PowerDMARC | OnDMARC | Cloudflare | MxToolbox | **Maily Flex v1** |
|---|---|---|---|---|---|---|---|---|
| Free checkers + generators | ✓ | ✓ | partial | ✓ | partial | – | ✓ | ✓ |
| RUA ingestion + dashboards | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | paid | ✓ |
| Sender identification | ✓ | ✓ | ✓ (best) | ✓ | ✓ | partial | partial | ✓ |
| Hosted DMARC (CNAME) | ✓ | – | Enforce | ✓ | ✓ | – | – | ✓ |
| Hosted SPF / 10-lookup fix | flattening | – | macros | macros+flat | flattening | – | $399 plan | flattening (no macros) |
| Hosted MTA-STS | ✓ | – | – | ✓ | ✓ | – | – | ✓ (all plans) |
| TLS-RPT | ✓ | ✓ | – | ✓ | ✓ | – | – | check + record (ingest v2) |
| Blacklist monitoring | ✓ | – | – | ✓ | – | – | ✓ | ✓ |
| Enforcement wizard | one-click | guidance | automated | ✓ | ✓ | – | – | ✓ with readiness gates |
| DMARCbis (RFC 9989) aware | ? | ? | ? | ✓ | ? | ? | ? | ✓ from day one |
| Published SMB pricing | ✓ | ✓ | ✗ | partial | ✗ | free | ✓ | ✓ |
| DNS-provider API integrations | ✓ | – | – | ✓ | – | native | – | later phase |
| RUF / failure reports | ✓ | ✓ | ✓ | ✓ | ✓ | – | – | later phase |
| MSP / white-label | ✓ | ✓ | – | ✓ | ✓ | – | – | later phase |

## 4. How hosted records work (patterns to implement, in our own way)

- **Hosted DMARC:** customer sets `_dmarc.example.com CNAME example.com._d.dns.mailyflex.com`. We publish the TXT at the target and can change policy without customer DNS access. (DMARC lookups follow CNAMEs.)
- **Hosted SPF, flattening:** customer sets `example.com TXT "v=spf1 include:example.com._s.dns.mailyflex.com -all"` (one lookup). We resolve all authorized includes to IP4/IP6, compact CIDRs, split into chained records under 255-char strings / ~450 bytes per record, and re-resolve on a schedule so provider IP changes are picked up. Macro-free, so it works with every receiver.
- **Hosted MTA-STS:** `_mta-sts` TXT (id changes on policy change) + `mta-sts.example.com` CNAME to our Worker, which serves `/.well-known/mta-sts.txt` over HTTPS for the customer's hostname (Cloudflare for SaaS custom hostnames issue the cert). `_smtp._tls` TXT CNAME'd to us for TLS-RPT.
- **Enforcement:** policy ladder `none → quarantine (t=y) → quarantine → reject (t=y) → reject`, each step gated on alignment pass-rate from real RUA data over N days.

## 5. Standards notes affecting the build

- **DMARC is now RFC 9989 (core), RFC 9990 (aggregate reporting), RFC 9991 (failure reporting)**, published 20 May 2026, replacing RFC 7489 and RFC 9091. Still `v=DMARC1`.
  - New tags: `np` (non-existent subdomain policy), `psd` (public-suffix flag: y/n/u), `t` (test mode, apply next-lower policy).
  - Historic tags: `pct`, `rf`, `ri`. Checker warns; generator omits them (offers `pct`+`t=y` together during ramp for legacy receivers).
  - Organizational domain via DNS Tree Walk instead of the Public Suffix List.
  - DMARC SPF evaluation uses MAIL FROM only (no HELO fallback).
- SPF RFC 7208: 10 DNS-mechanism lookups (include, a, mx, ptr, exists, redirect), 2 void-lookup limit, `ptr` discouraged, single record required.
- DKIM RFC 6376: keys ≥1024 bits (Gmail enforces), 2048 recommended; selectors are not discoverable from DNS, so we probe a dictionary of common provider selectors.
- MTA-STS RFC 8461, TLS-RPT RFC 8460, BIMI (requires DMARC at quarantine/reject; VMC/CMC for Gmail logo display).
- Mailbox-provider rules: Google, Yahoo and Microsoft (Outlook.com since May 2025) require SPF + DKIM + DMARC (≥ p=none, aligned) for 5,000+/day senders; Gmail moved to permanent 550 rejections from Nov 2025. This is the core marketing hook: "stop landing in spam / getting rejected".

## 6. Positioning for Maily Flex

1. **Transparent SMB pricing** against Valimail ($5k/yr) and MxToolbox ($129–399/mo).
2. **Hosted SPF without macros + hosted MTA-STS on every plan** (dmarcian and Cloudflare lack these).
3. **Plain-English fix list** with copy-paste records: MxToolbox's main weakness is "you must already know what to look for".
4. **DMARCbis-native** checker and generator from launch.
5. **Readiness-gated enforcement wizard**: safe path to p=reject using real report data.

## Sources
- EasyDMARC: easydmarc.com/pricing, easydmarc.com/llms.txt, G2 and TrustRadius listings
- dmarcian: dmarcian.com/plans, palisade.email dmarcian review, warmy.io tool page
- Valimail: valimail.com/products, valimail.com/ai-info, leadhaste.com "what is Valimail", warmy.io tool page
- PowerDMARC: powerdmarc.com/dmarc-rfc-9989, thectoclub.com PowerDMARC review
- Red Sift: redsift.com/pulse-platform/ondmarc/dynamic-spf, OnDMARC Dynamic SPF datasheet
- Cloudflare: blog.cloudflare.com/dmarc-management-ga, palisade.email Cloudflare comparison
- MxToolbox: mxtoolbox.com/public/upgradev2.aspx, powerdmarc.com MxToolbox review
- Standards: dmarc.org RFC 9989/9990/9991 announcement; suped.com DMARCbis summaries; Red Sift bulk-sender guide; folderly.com 2026 sender-requirements comparison
