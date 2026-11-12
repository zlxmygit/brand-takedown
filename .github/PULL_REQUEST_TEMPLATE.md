## Summary

Describe what this Pull Request changes and why.

## Checklist

- [ ] **100% Sanitized & Brand-Agnostic**: Zero real brand names, product models, private entities, live infringing URLs, or host-specific paths (`/Users/...`, `/home/...`, `C:\Users\...`).
- [ ] **Zero Third-Party Dependencies**: Uses Python 3.9+ standard library only.
- [ ] **Legal Precision**: Does not conflate Copyright (`DMCA`) with Trademark/Counterfeit or Design Patent claims; copyable English ```` ```text ```` blocks contain zero CJK characters.
- [ ] **SKILL.md Budget**: `SKILL.md` remains `<= 250` lines with valid relative links.
- [ ] **Verified Locally**: `python3 scripts/brand_registry.py validate --profile-file examples/sample-profile.json` and `python3 -m unittest discover -s tests -v` pass completely.
