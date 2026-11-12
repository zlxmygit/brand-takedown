"""Report local prerequisites and honest adapter capabilities; performs no network I/O."""
from __future__ import annotations
import json
import platform
import ssl
import sys
from zoneinfo import ZoneInfo


def diagnose() -> dict:
    errors = []
    if sys.version_info < (3, 11):
        errors.append("Python 3.11 or newer required")
    if platform.system() not in ("Linux", "Darwin"):
        errors.append("Only Linux/macOS local POSIX filesystems are supported")
    try:
        import fcntl  # noqa: F401
        ssl.create_default_context()
        ZoneInfo("America/New_York")
    except (ImportError, OSError, KeyError) as exc:
        errors.append(str(exc))
    return {"ok": not errors, "errors": errors, "python": platform.python_version(), "platform": platform.system(),
        "capabilities": {"direct_http": True, "rdap": True, "ct_radar": True, "approval_bound_eml": True,
                         "gmail_send": False, "gmail_sync": False, "browser_checkout": False,
                         "proxy": False, "public_archival": False, "scheduler": False},
        "scope": "Human-supervised draft/evidence workflow; not an autonomous enforcement service"}


if __name__ == "__main__":
    result = diagnose(); print(json.dumps(result, indent=2)); sys.exit(0 if result["ok"] else 2)
