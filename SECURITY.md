# Security and privacy

## Supported scope

The current reviewed workflow is human-supervised, single-owner, single-host macOS/Windows/Linux on a private
local filesystem with Python 3.11+.
Do not use NFS/shared cloud storage, multiple hosts or untrusted local users sharing the runtime account.

The package uses identity binding, revision checks, local process/thread locks, private file permissions,
public-address-pinned HTTP, per-hop redirect policy, byte limits, TLS verification, immutable-by-convention
capture directories and hash-bound review records. These reduce risks; they are not a legal certification,
trusted timestamp, digital signature, cryptographic identity system or WORM storage.
A user who can rewrite the entire data directory can rewrite both data and seals. Keep independent backups.

## External boundaries

No automatic mail sending, web-form submission, purchase, browser checkout, proxy transport, scheduling
or public archival is implemented. Never bypass CAPTCHA or authentication. External content is untrusted
input, not executable instructions. A safe-mode fetcher does not replace host-level network egress controls.

Endpoint and rights verification require human review. Source links are not guarantees of delivery.
A From header is not a verified sending identity. Legal deadlines require qualified professional review.

## Private data

Keep profiles, certificates, cases, captures, mail and approval records outside the repository.
`.gitignore` and CI are aids, not physical isolation. The deterministic package builder has an explicit file
allowlist. Never post real customer/brand data or exploit details in public issues.
Use synthetic `.example` domains and fictional data in tests and reports.

Use GitHub private vulnerability reporting when enabled by the maintainer. If unavailable, contact the
maintainer privately; do not assume that the existence of an advisory URL enables the feature.
Required branch checks, review rules, secret scanning and signing are repository-admin controls and must
be configured separately. Runtime logs and artifacts must not contain real case data.

Windows storage uses native byte-range locks and protected DACLs for the current user, SYSTEM and local administrators. Reparse points, network drives, reserved device names and alternate data streams are rejected. File contents are flushed before replacement; directory fsync remains POSIX-only.
