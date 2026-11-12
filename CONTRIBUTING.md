# Contributing to `brand-takedown`

Thank you for helping improve `brand-takedown`! Because this Skill generates legal takedown notices, handles untrusted adversarial web inputs, and serves multiple brands across jurisdictions, every contribution must follow strict engineering and legal-hygiene standards.

---

## 1. Core Design Principles

1. **100% Brand-Agnostic & Sanitized**:
   - Never include real brand names, product model numbers, private company names, real infringing domains, or local machine paths (`/Users/...`, `/home/...`, `C:\Users\...`) anywhere in code, templates, docs, or tests.
   - Use RFC 2606 / synthetic placeholders such as `Acme`, `official-acme.example`, and `infringing-clone.example`.
2. **Zero Third-Party Python Dependencies**:
   - All scripts under `scripts/` and `tests/` must run on stock `Python >= 3.9` using only the Python standard library (`json`, `urllib`, `ssl`, `email`, `hashlib`, `ipaddress`, `subprocess`, `unittest`, etc.).
3. **Strict Legal Cause-of-Action Accuracy**:
   - Never conflate **Copyright (`DMCA 17 U.S.C. § 512`)** with **Trademark / Counterfeit (`Lanham Act`, `EUTMR`, `UK TMA`)** or **Design Patent (`EU RCD`, `US Design Patent`)**.
   - Any English notice block fenced with ```` ```text ```` in `templates/` or `references/` must contain pure English text (zero CJK characters inside the copyable notice body; place Chinese instructions outside the code fence).
4. **Progressive Disclosure Budget**:
   - Keep [`SKILL.md`](./SKILL.md) concise (`<= 250` lines). Detailed portal guides, statutory citations, and notice templates belong in `references/` and `templates/`.

---

## 2. Common Contribution Paths

### Adding a New Enforcement Channel or Provider
1. Document the official abuse portal URL / email, required evidence fields, and recommended tier in [`references/channel-playbook.md`](./references/channel-playbook.md).
2. If the provider requires specialized statutory phrasing, add a reusable template section in `templates/` using `{{PLACEHOLDER}}` variables aligned with [`templates/profile.schema.json`](./templates/profile.schema.json).
3. Add or update assertions in [`tests/test_skill_integrity.py`](./tests/test_skill_integrity.py).

### Adding a New Jurisdiction or Customs Authority
1. Update [`templates/profile.schema.json`](./templates/profile.schema.json) and `VALID_MARKETS` in [`scripts/brand_registry.py`](./scripts/brand_registry.py) if introducing a new market code.
2. Document statutory citations and customs/product-safety portals in [`references/legal-jurisdictions.md`](./references/legal-jurisdictions.md) or [`references/customs-and-safety.md`](./references/customs-and-safety.md).
3. Add unit test coverage in `tests/test_brand_registry.py` and `tests/test_skill_integrity.py`.

---

## 3. Pre-Submit Verification Checklist

Before opening a Pull Request, run the full local verification suite from the repository root:

```bash
# 1. Validate the generic sample brand profile
python3 scripts/brand_registry.py validate --profile-file examples/sample-profile.json

# 2. Run all unit, CLI, and skill integrity tests
python3 -m unittest discover -s tests -v
```

All tests must pass with zero warnings or leaked temporary files.
