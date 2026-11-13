"""Deterministic allowlist-only source package; never bundle runtime brand data."""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import zipfile
from storage import safe_path

ROOT = Path(__file__).resolve().parent.parent
FILES = (
    '.github/ISSUE_TEMPLATE/bug_report.yml',
    '.github/ISSUE_TEMPLATE/channel_or_jurisdiction.yml',
    '.github/ISSUE_TEMPLATE/config.yml',
    '.github/PULL_REQUEST_TEMPLATE.md',
    '.github/branch-protection.json',
    '.github/workflows/ci.yml',
    '.github/workflows/psl-check.yml',
    '.github/workflows/release.yml',
    '.gitignore',
    'CHANGELOG.md',
    'CODE_OF_CONDUCT.md',
    'CONTRIBUTING.md',
    'LICENSE',
    'README.md',
    'SECURITY.md',
    'SKILL.md',
    'docs/audit-remediation.md',
    'docs/releases/v1.0.1.md',
    'docs/releases/v1.1.0.md',
    'docs/releases/v1.2.0.md',
    'docs/releases/v1.3.0.md',
    'docs/releases/v1.4.0.md',
    'docs/releases/v1.4.1.md',
    'docs/releases/v1.4.2.md',
    'docs/source-checksums.json',
    'examples/sample-profile.json',
    'references/channel-playbook.md',
    'references/customs-and-safety.md',
    'references/escalation-and-counter-notice.md',
    'references/host-contract.md',
    'references/followup-workflows.md',
    'references/maintenance.md',
    'references/legal-jurisdictions.md',
    'references/policy-sources.json',
    'references/public-suffix-license.md',
    'references/public_suffix_list.dat.gz',
    'scripts/brand_registry.py',
    'scripts/build_eml.py',
    'scripts/case_manager.py',
    'scripts/check_liveness.py',
    'scripts/ct_radar.py',
    'scripts/dns_json.py',
    'scripts/doctor.py',
    'scripts/domain_names.py',
    'scripts/html_tools.py',
    'scripts/image_hash.py',
    'scripts/package_skill.py',
    'scripts/packets.py',
    'scripts/recon_target.py',
    'scripts/radar_archive.py',
    'scripts/safe_http.py',
    'scripts/storage.py',
    'scripts/verify_source.py',
    'scripts/update_psl.py',
    'templates/notices-escalation-chaser.md',
    'templates/notices-registrar-hosting-cdn.md',
    'templates/notices-saas-payment-phishing.md',
    'templates/profile.schema.json',
    'tests/common.py',
    'tests/test_audit_regressions.py',
    'tests/test_brand_registry.py',
    'tests/test_case_manager.py',
    'tests/test_cli.py',
    'tests/test_followup_workflows.py',
    'tests/test_liveness_and_eml.py',
    'tests/test_packets.py',
    'tests/test_recon_and_radar.py',
    'tests/test_safe_http.py',
    'tests/test_skill_integrity.py',
    'tests/test_storage.py',
)


def build_package(output: Path, root: Path = ROOT) -> str:
    output = safe_path(output)
    root = safe_path(root)
    if output == root or root in output.parents:
        raise ValueError("Write build artifacts outside the repository")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = []
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(FILES):
            content = safe_path(root / name).read_bytes()
            info = zipfile.ZipInfo("brand-takedown/" + name, date_time=(2026, 11, 12, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, content)
            manifest.append(hashlib.sha256(content).hexdigest() + "  " + name)
        info = zipfile.ZipInfo("brand-takedown/SHA256SUMS.txt", date_time=(2026, 11, 12, 0, 0, 0))
        info.external_attr = 0o100644 << 16
        archive.writestr(info, "\n".join(manifest) + "\n")
    return hashlib.sha256(output.read_bytes()).hexdigest()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(); print(build_package(args.out) + "  " + str(args.out))
