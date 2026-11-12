---
name: brand-takedown
description: >-
  Brand-agnostic intellectual property enforcement, anti-counterfeiting, and relentless takedown engine.
  Use when the user reports cloned/impersonating websites, counterfeit product listings, typosquatting domains,
  or fake tracking scam sites; wants DMCA, trademark, design patent, EU DSA Art. 16, payment processor, SaaS,
  registrar, hosting/CDN, customs (CBP/EUIPO/HMRC/GACC), or product safety (CPSC/GPSR) complaints; or wants
  scheduled patrol, Gmail abuse-ticket monitoring, SLA chasers, UDRP/URS prep, or crt.sh typosquatting radar.
---

# Brand Takedown (`brand-takedown`)

Relentless, multi-brand enforcement engine. Brand credentials and case states live outside this skill folder (indexed at `~/.gemini/brand-protection/registry.json`, with brand data stored in user-chosen `<DATA_DIR>/<brand-slug>/` such as `~/.gemini/brand-protection/<brand-slug>/` or `<workspace>/brand-protection/<brand-slug>/`), keeping this skill 100% reusable across any brand.

Always resolve `<SKILL_DIR>` to the absolute path of the directory containing this `SKILL.md` file.

## Hard Safety & Legal Guardrails

1. **Allowlist Gate First**: Before probing or drafting against any URL, run [brand_registry.py](./scripts/brand_registry.py) `check-allowlist` (or `case_manager.py create`). Abort immediately if the domain matches `allowlist_domains` (official sites or authorized dealers).
2. **Strict Legal Routing**: Read [legal-jurisdictions.md](./references/legal-jurisdictions.md). Pair `DMCA (17 U.S.C. § 512)` strictly with copied photos/copy/code; route pure brand-name misuse or counterfeit goods to Trademark (`15 U.S.C. §§ 1114, 1125(a)` / `EUTMR`), Design Patent (`RCD` / US Design), and EU `DSA Regulation (EU) 2022/2065 Article 16`.
3. **Strike Order (Anti-Tip-Off)**: Lock local forensic evidence and submit Tier-1 strikes (Payment Processors + SaaS + Safe Browsing) *before* triggering Wayback snapshots or reverse-proxy CDN notices that forward your identity to the origin host.
4. **Anti-Cloaking Liveness Gate**: Treat bare `HTTP 404` with active DNS or `HTTP 200` missing brand keywords (`SUSPECTED_CLOAKING`) as unverified; transition to `WATCHLIST_RESURRECTION` only upon DNS suspension (`clientHold`/`NXDOMAIN`), platform suspension banner, or multi-vantage verification.
5. **Outbound Mail & CAPTCHA Discipline**: Verify corporate `Send-As` aliases via `gmail readonly sendas`. In unattended/cron runs, use `gmail mutate create-draft` only; in interactive runs, show recipients, subject, and attachments for explicit user confirmation before `gmail mutate send-with-attachment`. On web portals with CAPTCHAs, provide field-by-field copy blocks or prefill via the `browser` subagent up to the human verification step—never bypass CAPTCHAs.

---

## Routing: Pick the Active Branch

- **Branch 1 — Brand Onboarding**: Brand is not yet in `brand_registry.py list`, or user supplies new certificates/markets.
- **Branch 2 — Recon & Multi-Vector Strike**: User provides one or more infringing URLs/domains to take down.
- **Branch 3 — Patrol & Gmail Feedback Loop**: Manual or scheduled (`schedule` / `/schedule`) check of active cases, Gmail replies, liveness, infrastructure escapes, or `DMCA Counter-Notice` alerts.
- **Branch 4 — Relentless Escalation**: `case_manager.py due` reports overdue `ENFORCEMENT_SLA` channels.
- **Branch 5 — Proactive Radar**: User asks to hunt newly issued typosquatting certificates via `crt.sh`.

---

## Branch 1: Brand Onboarding (`Onboarding`)

1. Inspect `python3 <SKILL_DIR>/scripts/brand_registry.py list`.
2. Gather missing fields defined in [profile.schema.json](./templates/profile.schema.json): brand name, English/local legal entity, registered mailing address, signatory (`name`, `title`, `legal_email`, `phone`), `official_domains`, authorized dealer `allowlist_domains`, `target_markets` (`US`, `CA`, `EU`, `UK`, `AU`, `CN_EXPORT`, `GLOBAL`), and `product_risk_profile` (e.g. `high_power_lithium_mobility`).
3. If the user provides a folder of trademark/patent PDFs or images, inspect every certificate directly with `read_file` to extract exact registration numbers, classes, jurisdictions, expiry dates, and file paths.
4. Write the JSON profile and register it:
   ```bash
   python3 <SKILL_DIR>/scripts/brand_registry.py init --slug <slug> --data-dir ~/.gemini/brand-protection/<slug> --profile-file <tmp_profile.json>
   ```
5. Check `gmail readonly sendas`. If no `accepted` alias matches `official_domains`, remind the user to add their corporate legal email in Gmail `Send mail as` (while `.eml` generation remains immediately available).
- **Completion Criterion**: `brand_registry.py validate` exits `0` with zero errors, all referenced certificate paths exist, and `Send-As` status is reported.

---

## Branch 2: Recon, Evidence Vault & Initial Strike (`Recon & Strike`)

Consult [channel-playbook.md](./references/channel-playbook.md) and [legal-jurisdictions.md](./references/legal-jurisdictions.md) before drafting.

1. **Create Case (Idempotent + Allowlist Guard)**:
   ```bash
   python3 <SKILL_DIR>/scripts/case_manager.py create --slug <slug> --url "<target_url>" --types <TYPES...>
   ```
   Valid types: `COPYRIGHT_CLONE`, `TRADEMARK_IMPERSONATION`, `COUNTERFEIT_GOODS`, `DESIGN_PATENT_COPY`, `PHISHING_OR_FAKE_TRACKING`.
2. **Silent Forensic Recon & SHA-256 Vault**:
   ```bash
   python3 <SKILL_DIR>/scripts/recon_target.py run --slug <slug> --url "<target_url>" --case-dir "<case_dir>" [--proxy <url>] [--referer https://www.facebook.com/]
   ```
   - Capture full-page visual evidence into `<case_dir>/evidence/` using the `browser` subagent (or local headless Chrome fallback `/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --headless=new --screenshot="<case_dir>/evidence/screenshot.png" "<target_url>"`).
   - **Checkout Payment & AB-Cloak Probe**: When `recon-report.json` shows `needs_checkout_probe: true` on an active storefront, dispatch the `browser` subagent using benign target-market placeholder shipping details to reach the `Checkout` payment render stage (stop strictly before payment submission) to extract `Stripe pk_live_*`, `PayPal Merchant ID`, or hidden payment cloak B-site domains (`case_manager.py add-cloak --slug <slug> --case-dir "<case_dir>" --domain "<b_domain>"`).
   - Re-lock hashes after adding screenshots:
     ```bash
     python3 <SKILL_DIR>/scripts/recon_target.py refresh-manifest --case-dir "<case_dir>"
     ```
   - Report any shared `ga_ids`, `meta_pixel_ids`, or `shopify_domain` clusters across cases to uncover sister scam sites.
3. **Register Strike Channels & Render Complete Packets**:
   - **Wave 1 (`T+0`, `ENFORCEMENT_SLA`, 48h–120h)**: Payment processors, SaaS (`Shopify`/`Shoplazza`/`Shopline`), Safe Browsing/SmartScreen/Netcraft, Search & Ad networks using [notices-saas-payment-phishing.md](./templates/notices-saas-payment-phishing.md).
   - **Wave 2 (Post-Vault, `ENFORCEMENT_SLA`, 72h)**: Run `recon_target.py archive-wayback --slug <slug> --url "<target_url>"`, then generate Registrar `clientHold` + `EU NIS2 Art. 28` registrant disclosure, ESP mail abuse, and Hosting/CDN (`US DMCA + Lanham` or `EU DSA Art. 16 + EUTMR + RCD + GPSR`) packets using [notices-registrar-hosting-cdn.md](./templates/notices-registrar-hosting-cdn.md).
   - **Wave 3 (`REGULATORY_FILING` & Domain Recovery)**: When applicable, prepare US `CBP`, `CBSA`, `EUIPO IPEP`, `UK HMRC`, China `GACC` export customs, and `CPSC` / `EU Safety Gate` filings per [customs-and-safety.md](./references/customs-and-safety.md), plus consolidated `URS`/`UDRP` analysis per [escalation-and-counter-notice.md](./references/escalation-and-counter-notice.md).
   - Render every notice into `<case_dir>/packets/` with **zero unfilled `{{...}}` placeholders**, build multi-attachment `.eml` files via [build_eml.py](./scripts/build_eml.py), and register each channel via `case_manager.py add-channel`.
- **Completion Criterion**: Every target URL has a verified `evidence-manifest.json`, all applicable channels are logged in `case.json` with accurate `channel_class` (`ENFORCEMENT_SLA` vs `REGULATORY_FILING`), and ready-to-send `.md`/`.eml` packets exist in `<case_dir>/packets/`.

---

## Branch 3: Scheduled Patrol & Gmail Feedback Loop (`Patrol`)

Can be run on demand or scheduled via the `schedule` tool (e.g. every 12h or daily cron):

1. **Sync Gmail Replies**: Run `gmail readonly search` / `gmail readonly read` for each active case's domain, provider, and `ticket_ref`:
   - Extract new ticket IDs and update `case_manager.py update-channel --case-dir "<case_dir>" --channel-id <id> --ticket-ref "<ref>" --status ACKNOWLEDGED`.
   - Flag `NEED_MORE_INFO` requests and draft responses with supporting certificates.
   - **P0 Counter-Notice Defense**: If any reply contains a `DMCA Counter-Notice`, immediately run `case_manager.py counter-notice` to compute the 10-business-day statutory deadline and execute the two-prong rebuttal in [escalation-and-counter-notice.md](./references/escalation-and-counter-notice.md) (expose fake/perjurious address + lock via Registered Trademark, Design Patent, and Payment Fraud).
2. **Run Anti-Cloaking Liveness & Escape Probe**:
   ```bash
   python3 <SKILL_DIR>/scripts/check_liveness.py patrol --slug <slug>
   ```
   - If `verdict == "ACTIVE_ESCAPED_INFRA"`, run Branch 2 recon against the new hosting IPs/domain and open fresh host takedown channels.
   - If `resurrected_alert == true`, alert the user at top priority and re-open enforcement.
3. **Check Overdue SLAs**: Run `python3 <SKILL_DIR>/scripts/case_manager.py due --slug <slug>` and hand any overdue items directly to Branch 4.
- **Completion Criterion**: All active and watchlist cases have fresh `last_liveness_probe` timestamps, Gmail threads are reconciled, and any overdue `ENFORCEMENT_SLA` channel has transitioned into Branch 4.

---

## Branch 4: Three-Tier Relentless Escalation (`Escalate`)

Read [escalation-and-counter-notice.md](./references/escalation-and-counter-notice.md) and render from [notices-escalation-chaser.md](./templates/notices-escalation-chaser.md):

1. **Tier 1 → Tier 2 (`SLA Breach Chaser`)**: Cite original `submitted_at`, `ticket_ref`, fresh probe timestamp, and explicit **Loss of Safe Harbor Immunity** (`17 U.S.C. § 512(c)` / `EU DSA Art. 6`) + product safety liability warning. Set 48h final remediation window.
2. **Tier 2 → Tier 3 (`Upstream & Regulatory Escalation`)**:
   - Unresponsive Registrar → File **ICANN Contractual Compliance** (`2013 RAA § 3.18`) + TLD **Registry** (`serverHold`) + EU **NIS2 Art. 28** authority complaint.
   - Unresponsive Reseller Host → `whois <direct_dns_ip>` to hit upstream **BGP ASN / Tier-1 Data Center** abuse.
   - Unresponsive EU Intermediary → File **Article 53 DSA** complaint with the Member State **Digital Services Coordinator (DSC)**.
3. Advance tier via `case_manager.py escalate`, build `.eml` via `build_eml.py`, and create Gmail drafts (`gmail mutate create-draft`) or send upon user confirmation.
- **Completion Criterion**: Zero overdue `ENFORCEMENT_SLA` channels remain un-escalated, and corresponding Tier-2/Tier-3 drafts or `.eml` files are saved.

---

## Branch 5: Proactive Certificate Transparency Radar (`Radar`)

```bash
python3 <SKILL_DIR>/scripts/ct_radar.py --slug <slug>
```
Inspect `new_suspicious_domains`, verify live storefronts, present newly discovered typosquats to the user, and feed confirmed infringers into Branch 2.
- **Completion Criterion**: `radar_seen.json` is updated and every newly surfaced domain is triaged.
