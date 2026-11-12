from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from brand_registry import is_allowlisted_url, load_brand_profile, normalize_hostname


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp_path, path)


def extract_candidate_domains_from_crt(
    crt_rows: list[dict],
    allowlist_domains: list[str],
    already_seen: set[str],
) -> list[str]:
    candidates: set[str] = set()
    normalized_seen = {normalize_hostname(s) for s in already_seen if normalize_hostname(s)}

    for row in crt_rows:
        if not isinstance(row, dict):
            continue
        raw_names = str(row.get("name_value", "")) + "\n" + str(row.get("common_name", ""))
        for line in raw_names.splitlines():
            token = line.strip().lower()
            if not token or " " in token or "@" in token:
                continue
            if token.startswith("*."):
                token = token[2:]
            host = normalize_hostname(token)
            if not host or "." not in host:
                continue
            if host in normalized_seen:
                continue
            if is_allowlisted_url(host, allowlist_domains):
                continue
            candidates.add(host)

    return sorted(candidates)


def _fetch_crt_json(keyword: str) -> list[dict]:
    encoded_query = quote(f"%{keyword.strip().lower()}%")
    url = f"https://crt.sh/?q={encoded_query}&output=json"
    try:
        proc = subprocess.run(
            ["/usr/bin/curl", "-sS", "--max-time", "30", url],
            capture_output=True,
            text=True,
            timeout=35,
            check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        parsed = json.loads(proc.stdout)
        return parsed if isinstance(parsed, list) else []
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []


def run_radar_scan(brand_dir: Path, profile: dict) -> dict:
    seen_path = brand_dir.expanduser().resolve() / "radar_seen.json"
    already_seen: set[str] = set()
    if seen_path.is_file():
        try:
            loaded = json.loads(seen_path.read_text(encoding="utf-8"))
            if isinstance(loaded.get("seen_domains"), list):
                already_seen = {str(d).lower() for d in loaded["seen_domains"]}
        except json.JSONDecodeError:
            already_seen = set()

    keywords = profile.get("keyword_watch_patterns") or [profile.get("brand_slug", "")]
    allowlist = profile.get("allowlist_domains", [])

    all_rows: list[dict] = []
    for kw in keywords:
        kw_clean = str(kw).strip()
        if len(kw_clean) >= 3:
            all_rows.extend(_fetch_crt_json(kw_clean))

    newly_discovered = extract_candidate_domains_from_crt(all_rows, allowlist, already_seen)
    updated_seen = sorted(already_seen.union(newly_discovered))

    _atomic_write_json(
        seen_path,
        {
            "last_scanned_at": _utc_now_iso(),
            "keywords_queried": keywords,
            "seen_domains": updated_seen,
        },
    )

    return {
        "scanned_at": _utc_now_iso(),
        "keywords_queried": keywords,
        "new_suspicious_count": len(newly_discovered),
        "new_suspicious_domains": newly_discovered,
    }


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Proactive Certificate Transparency (crt.sh) typosquatting radar.")
    parser.add_argument("--slug", required=True, help="Registered brand slug")
    args = parser.parse_args(argv)

    brand_dir, profile = load_brand_profile(args.slug)
    result = run_radar_scan(brand_dir, profile)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(_main())
