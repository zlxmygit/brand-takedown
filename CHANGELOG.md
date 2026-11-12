# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-12

### Added
- **Progressive-Disclosure Skill Router (`SKILL.md`)**: 5-branch workflow router covering Multi-Brand Onboarding, Forensic Recon & Tiered Takedown, Gmail & Liveness Patrol, 3-Tier Escalation & Counter-Notice Defense, and `crt.sh` Certificate Transparency Radar.
- **Multi-Brand Registry (`scripts/brand_registry.py` & `templates/profile.schema.json`)**: Schema validation, brand profile registration outside the repository, and hardened allowlist URL guard defeating backslash (`\`) and `userinfo (@)` parser differentials.
- **Forensic Vault & Storefront Fingerprinting (`scripts/recon_target.py`)**: Direct unproxied `WHOIS`, `DNS (A/AAAA/CNAME/NS/MX/TXT)`, and `TLS` X.509 `SHA-256` capture; isolated optional-proxy HTML fetch; extraction of underlying `.myshopify.com` domains, `Shop ID`, `Stripe pk_live_*`, `PayPal Merchant ID`, `GA4`, and `Meta Pixel` identifiers; `SHA-256` manifest synchronization; and post-vault Wayback Machine archival.
- **Persistent Case & SLA State Machine (`scripts/case_manager.py`)**: Separation of `ENFORCEMENT_SLA` vs. `REGULATORY_FILING` channels, 3-tier overdue escalation scanner, linked AB payment cloak domain tracking, and weekend-aware 10-business-day `DMCA Counter-Notice` deadline calculation.
- **Anti-Cloaking Liveness & Escape Probe (`scripts/check_liveness.py`)**: Multi-signal verification distinguishing `CONFIRMED_DOWN_DNS` (`clientHold`), `CONFIRMED_DOWN_PLATFORM`, `SUSPECTED_CLOAKING` (bait-and-switch safe pages), `ACTIVE_ESCAPED_INFRA` (origin IP migration), and 90-day `RESURRECTED_ALERT` monitoring.
- **Proactive Typosquatting Radar (`scripts/ct_radar.py`)**: Incremental `crt.sh` Certificate Transparency log scanner with wildcard normalization and allowlist deduplication.
- **Corporate Identity `.eml` Builder (`scripts/build_eml.py`)**: RFC 5322 compliant multipart email generator preserving corporate `From` / `Reply-To` headers and UTF-8 multi-file PDF/PNG evidence attachments.
- **Multi-Jurisdiction Legal & Customs Playbooks (`references/` & `templates/`)**: Full coverage for US (`DMCA 17 U.S.C. § 512`, `Lanham Act`, `US Design Patent`, `CBP`, `CPSC`), Canada (`Notice & Notice`, `CBSA RFA`), EU (`DSA Art. 16`, `NIS2 Art. 28`, `EUTMR`, `RCD`, `EUIPO IPEP AFA`, `GPSR` & `Safety Gate`), UK (`TMA`, `Passing Off`, `HMRC AFA`), China Export Customs (`GACC`), and `ICANN / URS / UDRP` domain disputes.
- **Test Suite & CI (`tests/` & `.github/workflows/ci.yml`)**: Zero-dependency unit and CLI integration test suite verified on Python 3.9+ across macOS and Linux.
