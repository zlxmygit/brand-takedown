# Contributing

Use Python 3.11+ standard library at runtime. Keep tests offline except a loopback-only HTTP server.
Use only fictional `.example` identities; never attach real profiles, certificates, notices or case history.

Before a change is accepted:

```bash
python3 -m compileall -q scripts tests
python3 scripts/doctor.py
python3 scripts/brand_registry.py validate --profile-file examples/sample-profile.json
python3 -m unittest discover -s tests -v
python3 scripts/package_skill.py --out /tmp/brand-takedown-reviewed.zip
```

Add negative-path tests for policy changes. Do not replace failing safety assertions with keyword checks.
Keep the regression's intended behavior and audit mapping explicit. New schema keywords must be supported
and tested by the local validator; it is not a general-purpose JSON Schema implementation.

External actions need real capability discovery, explicit user approval, idempotency and independent
integration tests. Do not claim delivery, continuous monitoring or takedown success from prepared drafts.
New legal text needs primary sources, jurisdiction/role scope and no guaranteed outcome language.
Pin third-party CI actions by reviewed commit SHA. Preserve protected-branch/review controls.
