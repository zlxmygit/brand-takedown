"""Check the local Python, timezone, TLS and private storage environment."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import ssl
import sys
import tempfile

from runtime_support import configure_cli, load_timezone
from storage import atomic_write_json, locked, read_json, safe_path


def diagnose(data_dir: Path | None = None) -> dict:
    errors = []
    if sys.version_info < (3, 11):
        errors.append("Python 3.11 or newer required")
    if platform.system() not in ("Linux", "Darwin", "Windows"):
        errors.append("Supported systems: macOS, Windows and Linux")
    try:
        ssl.create_default_context()
        load_timezone("America/New_York")
    except (ImportError, ValueError, OSError, KeyError) as exc:
        errors.append(str(exc))
    try:
        parent = safe_path(data_dir) if data_dir is not None else None
        with tempfile.TemporaryDirectory(prefix="brand-takedown-check-", dir=parent) as temporary:
            path = Path(temporary) / "check.json"
            with locked(path.with_suffix(".lock")):
                atomic_write_json(path, {"storage": "中文读写"})
                if read_json(path) != {"storage": "中文读写"}:
                    raise OSError("Local storage round-trip failed")
    except (ValueError, OSError) as exc:
        errors.append(str(exc))
    return {"ok": not errors, "errors": errors, "python": platform.python_version(), "platform": platform.system(),
        "storage": {"lock_backend": "msvcrt" if os.name == "nt" else "flock",
                    "private_permissions": "Windows DACL" if os.name == "nt" else "POSIX 0700/0600",
                    "file_fsync": True, "directory_fsync": os.name != "nt"},
        "capabilities": {"direct_http": True, "rdap": True, "ct_radar": True, "approval_bound_eml": True,
                         "gmail_send": False, "gmail_sync": False, "browser_checkout": False,
                         "proxy": False, "public_archival": False, "scheduler": False}}


if __name__ == "__main__":
    configure_cli()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, help="Check an existing local data directory")
    args = parser.parse_args()
    result = diagnose(args.data_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    sys.exit(0 if result["ok"] else 2)
