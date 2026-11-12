# Security & Data Privacy Policy (`SECURITY.md`)

## 1. Zero Private Brand Data in Public Repository

`brand-takedown` is strictly a **generic, brand-agnostic enforcement engine**.

- **NEVER** commit, upload, or paste real trademark/patent certificate PDFs, live `profile.json` files, case directories (`cases/`), forensic snapshots (`raw.html`, screenshots, `.har`), or `.eml` notices into Issues, Pull Requests, or Discussions.
- All runtime brand profiles and case vaults belong outside this repository (default: `~/.gemini/brand-protection/<brand_slug>/`) and are blocked by [`.gitignore`](./.gitignore) and automated CI checks in [`.github/workflows/ci.yml`](./.github/workflows/ci.yml).

## 2. Built-in Security Hardening

This Skill processes untrusted URLs, HTML pages, DNS responses, and email metadata controlled by adversarial counterfeit/phishing operators. The codebase enforces the following defensive boundaries:

1. **Allowlist Guard Against Parser Differentials**:
   - `brand_registry.py` normalizes backslashes (`\`), strips `userinfo` (`@`), validates RFC 1123 hostnames, and enforces exact/subdomain allowlist matching before any recon, case creation, or takedown action can run.
2. **CLI Option & Protocol Injection Defense**:
   - External tools (`curl`, `whois`, `dig`, `openssl`) are always invoked via `subprocess.run([...], shell=False)` with validated hostnames, `--proto =http,https`, `--globoff`, and explicit `--` URL terminators where supported.
3. **Forensic Chain-of-Custody Isolation**:
   - `WHOIS`, `DNS`, and direct `TLS` certificate fingerprinting always bypass user HTTP proxies (`--noproxy '*'`) so proxy exit nodes never contaminate origin infrastructure evidence.
4. **CAPTCHA & Access Control Compliance**:
   - The Skill never attempts to bypass, solve, or automate around CAPTCHAs, Cloudflare Turnstile, or authentication gates.

## 3. Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.0.x` (`main`) | Yes |
| `< 1.0.0` | No |

## 4. Reporting a Vulnerability

If you discover a security vulnerability (such as URL allowlist bypass, command argument injection, path traversal, or unintended proxy/DNS leakage):

1. **Do NOT open a public GitHub Issue** with exploit details.
2. Please use **GitHub Private Vulnerability Reporting** (`Security` tab -> `Report a vulnerability`) on https://github.com/zlxmygit/brand-takedown/security/advisories/new.
3. Include minimal reproduction steps using synthetic domains (e.g., `official-acme.example` and `infringing-clone.example`). We aim to triage reports within **72 hours**.
