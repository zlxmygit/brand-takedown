# Changelog

## Unreleased — safety reconstruction (2026-11-12)

Breaking: Python 3.11+, case schema v2, brand-bound case paths, approval-bound EML CLI, explicit receipt
recording for SUBMITTED. No in-place legacy case migration. Old evidence is never silently resealed.

Added: collision-free case identities; local process/thread locks and revision conflicts; strict profile
validation; pinned public HTTP with redirect policy; IANA-discovered RDAP; separate evidence captures and
seal verification; independent legal tasks; persistent CT triage; claim/evidence/rights packet gates;
human approval of exact payload; capability doctor; allowlist-only reproducible source packaging.

Changed: all-target observations instead of automatic case closure; escalation planning separate from
transmission; supplement and Tier-3 review queues remain visible. Counter-notice windows are explicitly
weekend-only estimates requiring counsel, not certified legal deadlines.

Removed/disabled: unsafe proxy/referer paths, automatic Wayback publication, assumed Gmail/browser/scheduler
capabilities, unverified bulk contact lists and guarantees of permanent blocking or automatic liability.

Verification: offline regression, multiprocessing storage and loopback HTTP tests; real external complaint,
mail, browser, customs and court integration are not executed or certified by the test suite.

## 1.0.0 — 2026-11-12

Historical initial release. Retained for provenance; not approved for unattended real enforcement.
