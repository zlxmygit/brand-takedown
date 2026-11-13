"""Run checkout and installed-package checks without shell-specific commands."""
from __future__ import annotations

import argparse
import compileall
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

from package_skill import ROOT, build_package
from runtime_support import configure_cli


def run_python(root: Path, *arguments: str) -> None:
    subprocess.run([sys.executable, *arguments], cwd=root, check=True)


def smoke() -> None:
    if not compileall.compile_dir(ROOT / 'scripts', quiet=1) or not compileall.compile_dir(ROOT / 'tests', quiet=1):
        raise ValueError('Python compilation failed')
    run_python(ROOT, 'scripts/doctor.py')
    run_python(ROOT, 'scripts/brand_registry.py', 'validate', '--profile-file', 'examples/sample-profile.json')


def tracked_guard() -> None:
    result = subprocess.run(['git', 'ls-files', '-z'], cwd=ROOT, capture_output=True, check=True)
    pattern = re.compile(r'(^|/)(cases|certificates|evidence|packets)/|(^|/)(profile|registry|case|radar_seen|evidence-manifest|recon-report)\.json$|\.(eml|pdf|png|jpe?g|har|pem|key|sqlite3|sqlite3-journal|sqlite3-wal|sqlite3-shm)$|(^|/)\.psl-update\.json$|(^|/)\.env($|\.)', re.I)
    bad = [p for p in result.stdout.decode('utf-8').split('\0') if pattern.search(p)]
    if bad:
        raise ValueError('Private runtime artifacts tracked: ' + ', '.join(bad))
    print('Tracked private artifact check passed')


def installed_package() -> None:
    with tempfile.TemporaryDirectory(prefix='brand-takedown-package-') as temporary:
        directory = Path(temporary)
        first, second = directory / 'first.zip', directory / 'second.zip'
        a, b = build_package(first), build_package(second)
        if a != b or first.read_bytes() != second.read_bytes():
            raise ValueError('Repeated builds differ')
        with zipfile.ZipFile(first) as archive:
            archive.extractall(directory / 'installed')
        installed = directory / 'installed/brand-takedown'
        for row in (installed / 'SHA256SUMS.txt').read_text(encoding='utf-8').splitlines():
            digest, name = row.split('  ', 1)
            if hashlib.sha256((installed / name).read_bytes()).hexdigest() != digest:
                raise ValueError('Installed file mismatch: ' + name)
        run_python(installed, 'scripts/verify_source.py')
        run_python(installed, '-m', 'unittest', 'discover', '-s', 'tests', '-v')
        print('Installed package and deterministic build passed: ' + a, flush=True)


if __name__ == '__main__':
    configure_cli()
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--smoke', action='store_true')
    group.add_argument('--tracked', action='store_true')
    group.add_argument('--package', action='store_true')
    args = parser.parse_args()
    if args.smoke:
        smoke()
    elif args.tracked:
        tracked_guard()
    else:
        installed_package()
