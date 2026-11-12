# Audit remediation ledger — 2026-11-12

Baseline: `db6dcec519dccd2b7bd67d9ec762fd18e8aed784`. All examples and tests are synthetic.
This ledger describes implementation and verification boundaries; it is not a certification or legal opinion.
**Implemented** means the scoped code change has regression coverage. **Restricted** means the unsafe feature
was disabled or requires explicit human review, not that a replacement external integration was completed.
**Partial** identifies repository-administration or professional-validation work outside this patch.

|ID|Finding / disposition|Implementation / regression evidence|Status|
|---|---|---|---|
|BT-01|Colliding case paths|UUID case IDs, normalized-host merge under lock; case/CLI collision tests|Implemented|
|BT-02|Cross-brand/case/target mixing|Persistent brand identity, immutable directory binding, case-target check; brand/recon/CLI tests|Implemented|
|BT-03|Lost concurrent state updates|Reentrant thread locks + POSIX flock, unique temp files, fsync, revision checks; 4-process/48-update test|Implemented|
|BT-04|Corruption silently reset|Registry, case and CT state fail visibly; corruption tests|Implemented|
|BT-05|Weak profile validation|Runtime closed-schema subset, exact types/enums, conditional registered-right checks; schema tests|Implemented|
|BT-06|Redirect SSRF / allowlist bypass|Per-hop check, all-address public test, pinned numeric connection, verified TLS, bounded responses; loopback HTTP tests|Implemented|
|BT-07|Incomplete allowlist enforcement|Fresh profile checks for cases, captures, patrol, linked leads, packet preparation and approval|Implemented|
|BT-08|Failed fetch marked evidence locked|FAILED/PARTIAL captures remain ineligible; nonzero CLI; recon tests|Implemented|
|BT-09|Evidence overwrite/stale files|New CAP UUID directory each attempt; no reused platform file cache|Implemented|
|BT-10|Rehash silently accepts modification|Refresh is verification only; immutable original manifest digest in case; tamper tests|Implemented|
|BT-11|Nested evidence/symlink holes|Recursive inventory, regular files only, symlink rejection|Implemented|
|BT-12|Original bytes altered by decoding|Store raw.bin bytes; decode only untrusted hints; invalid-UTF8 test|Implemented|
|BT-13|Incomplete DNS falsely confirms down|Recursive DNS is labeled non-authoritative; uncertainty never closes a case|Implemented|
|BT-14|Page-controlled suspension banners|Hidden markup filtered; banners remain review-only leads|Implemented|
|BT-15|Only first URL checked|Every registered URL and linked lead probed; errors isolated|Implemented|
|BT-16|Fingerprint/keyword/IP overclaims|Structured unverified leads; no automated ownership, infringement or origin attribution|Restricted|
|BT-17|Patrol erases legal alert|Independent open legal tasks and due queue; liveness cannot clear them|Implemented|
|BT-18|Invalid escalation/submission transitions|Explicit approval-bound receipt, no early/closed/unsubmitted escalation, staging is not sending|Implemented|
|BT-19|Supplement/Tier3 tasks disappear|NEED_MORE_INFO and Tier3 remain in due review queue|Implemented|
|BT-20|Incorrect counter-notice deadline|Separate provider/rightsholder timestamps; labeled weekday-only 10–14 estimate, unknown start stays unknown; counsel confirmation required|Restricted|
|BT-21|CT outage looks like zero findings|Structured per-keyword errors, nonzero CLI, successful timestamp not advanced by total failure|Implemented|
|BT-22|Untriaged CT candidates consumed|Persistent pending candidates, explicit named triage and rationale|Implemented|
|BT-23|WHOIS-only registration lookup|IANA-bootstrap HTTPS RDAP, explicit errors/subdomain manual fallback; no hard-coded WHOIS executable|Implemented|
|BT-24|Unimplemented host/90-day promises|Capability doctor and host contract; Gmail/browser/scheduler/90-day unattended promises removed|Restricted|
|BT-25|Prompt-injection/data trust boundary|External text treated as evidence, independent provider provenance, no auto-send; behavioral host red-team remains unvalidated|Restricted|
|BT-26|Unsupported severe legal allegations|Claim/right/territory/evidence/fair-use review records; no automatic brand-risk paragraph; exact packet approval|Restricted|
|BT-27|Internal SLA treated as law/liability|Internal follow-up wording only; no automatic liability or suspension consequence|Restricted|
|BT-28|Guaranteed permanent hard lock/perjury claims|Removed; legitimate response/counter-notice review and counsel referral|Restricted|
|BT-29|False confidentiality promise|Evidence before any notice; explicit warning that provider may share complaint/contact information|Restricted|
|BT-30|DSA scope/roles/recipients confused|EU-hosting scoped route, separate UK analysis, correct notice/affected-recipient distinction in guidance|Restricted|
|BT-31|NIS2 unconditional disclosure promise|No automated disclosure demand; reasoned-response and national-implementation review guidance|Restricted|
|BT-32|Automatic customs seizure/full-EU claim|Regulatory information only; no automatic filing or guaranteed seizure; scope reviewed manually|Restricted|
|BT-33|Risk category becomes hazard accusation|Specific legal requirement and observed defect mandatory; category does not create a claim|Restricted|
|BT-34|Unverified complaint endpoints|Independent HTTPS provenance, named verification/time and freshness requirement; no guessed bulk-email list|Restricted|
|BT-35|Unreviewed or malformed EML|Strict addresses, no placeholders, bounded attachments, SMTP CRLF, approved packet CLI, unsent-only marker|Implemented|
|BT-36|Wayback reports success without archive|Automatic publication disabled and nonzero response; manual archival validation required|Restricted|
|BT-37|Hard-coded binaries / patrol aborts|Stdlib HTTP/DNS/RDAP, doctor, per-case failure isolation, structured exits|Implemented|
|BT-38|Weak test coverage|Negative behavior, multiprocess, actual loopback HTTP and subprocess workflow tests; no real complaints|Implemented|
|BT-39|Privacy/supply-chain overclaims|Explicit-file deterministic packaging, private modes, pinned CI actions; branch protection/private-reporting settings not changed|Partial|

## Verification model

Run `python3 -m unittest discover -s tests -v`, `python3 -m compileall -q scripts tests`,
`python3 scripts/doctor.py`, and sample profile validation. Test counts belong in the execution report,
not in a perpetual claim in this document. CI checks Linux/macOS and Python 3.11/3.13.
The suite uses mocked external provider responses and real HTTP bound to loopback through test-only
transport injection. Production exposes no allow-private-network override.

The audit's original Rxx probes asserted defective behavior. Their relevant cases are replaced by
safe-behavior regression tests, rather than being presented as passing production acceptance tests.
The formerly inconsistent README example was already corrected upstream and is not counted twice.

## Remaining limits and migration

No real Gmail/portal/browser/checkout integration, national judicial-calendar engine, comprehensive
cross-jurisdiction legal renderer, external timestamp authority or WORM archive is claimed. Approval is a
local workflow attestation, not a cryptographic identity signature. The same OS owner can rewrite all state.
Use private local POSIX storage; locks are not a distributed database or NFS concurrency guarantee.
Network egress controls and sandboxing remain required defense in depth for adversarial evidence handling.
RDAP/CT live service availability and genuine legal outcomes are not established by offline tests.

Old schema-1 data is refused rather than silently upgraded. Back up first, review in an isolated copy,
then create fresh schema-2 records and explicitly label/import historical documents. Do not rewrite old
hashes, reconstruct missing evidence as authentic, or substitute import time for original capture time.
Re-enter and independently review open counter-notices before resuming operational work.

Repository owners should separately enable branch protection, required reviews/checks, private security
reporting, and organization-level security controls. This patch does not claim those administrative
settings were changed or that version 1.0.0 release assets were replaced.
