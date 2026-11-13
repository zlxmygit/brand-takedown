"""Shared CLI encoding and IANA timezone loading on all supported systems."""
from __future__ import annotations

import sys
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def configure_cli() -> None:
    # Pipes and redirected output must remain UTF-8 even on a legacy Windows locale.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")


def load_timezone(name: str):
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(
            f"IANA timezone unavailable: {name}. Check the timezone name; "
            "install the platform dependencies with: python -m pip install -r requirements.txt"
        ) from exc
