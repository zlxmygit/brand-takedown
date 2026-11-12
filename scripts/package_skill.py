"""Deterministic allowlist-only source package; never bundle runtime brand data."""
from __future__ import annotations
import argparse
import hashlib
from pathlib import Path
import zipfile
from storage import safe_path

ROOT = Path(__file__).resolve().parent.parent
FILES = (
    "SKILL.md", "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "CHANGELOG.md",
    "scripts/brand_registry.py", "scripts/case_manager.py", "scripts/recon_target.py", "scripts/check_liveness.py",
    "scripts/ct_radar.py", "scripts/build_eml.py", "scripts/storage.py", "scripts/safe_http.py", "scripts/packets.py",
    "scripts/doctor.py", "scripts/package_skill.py", "templates/profile.schema.json", "examples/sample-profile.json",
    "references/channel-playbook.md", "references/legal-jurisdictions.md", "references/customs-and-safety.md",
    "references/escalation-and-counter-notice.md", "references/policy-sources.json", "references/host-contract.md",
    "templates/notices-saas-payment-phishing.md", "templates/notices-registrar-hosting-cdn.md", "templates/notices-escalation-chaser.md",
    "docs/audit-remediation.md", "tests/common.py", "tests/test_brand_registry.py", "tests/test_case_manager.py",
    "tests/test_recon_and_radar.py", "tests/test_liveness_and_eml.py", "tests/test_safe_http.py", "tests/test_storage.py",
    "tests/test_packets.py", "tests/test_skill_integrity.py", "tests/test_cli.py",
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
