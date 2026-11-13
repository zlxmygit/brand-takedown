"""Verify the same complete source manifest in a checkout or an extracted package."""
import hashlib
import json
from pathlib import Path
import re
import sys
from storage import read_json, safe_path


def verify_source(root: Path) -> int:
    root = safe_path(root)
    manifest = read_json(root / 'docs/source-checksums.json')
    entries = manifest.get('files')
    if not isinstance(entries, dict) or not entries:
        raise ValueError('Empty or invalid source manifest')
    for name, expected in entries.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise ValueError('Invalid source manifest entry')
        path = safe_path(root / relative)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'Source manifest mismatch: {name}')
    return len(entries)


if __name__ == '__main__':
    from runtime_support import configure_cli
    configure_cli()
    try:
        count = verify_source(Path(__file__).resolve().parent.parent)
        print(json.dumps({'verified_files': count}))
    except (ValueError, OSError) as exc:
        print(json.dumps({'error': str(exc)}), file=sys.stderr)
        sys.exit(2)
