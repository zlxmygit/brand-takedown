"""CT search with explicit errors and persistent human triage, not infringement detection."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from urllib.parse import quote

from brand_registry import DEFAULT_REGISTRY_PATH, is_allowlisted_url, load_brand_profile, normalize_hostname, profile_allowlist, profile_from_dir, utc_now
from safe_http import fetch
from storage import atomic_write_json, locked, read_json, safe_path


def extract_candidate_domains_from_crt(crt_rows: list[dict], allowlist_domains: list[str], already_seen: set[str]) -> list[str]:
    candidates = set()
    for row in crt_rows:
        if not isinstance(row, dict):
            continue
        for name in (str(row.get("name_value", "")) + "\n" + str(row.get("common_name", ""))).splitlines():
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            host = normalize_hostname(name)
            if host and host not in already_seen and not is_allowlisted_url(host, allowlist_domains):
                candidates.add(host)
    return sorted(candidates)


def _fetch_crt_json(keyword: str) -> list[dict]:
    response = fetch("https://crt.sh/?q=" + quote("%" + keyword.lower() + "%", safe="") + "&output=json")
    if response.status != 200:
        raise ValueError(f"CT service HTTP {response.status}")
    rows = json.loads(response.body)
    if not isinstance(rows, list):
        raise ValueError("CT service returned a non-list JSON response")
    return rows


def run_radar_scan(brand_dir: Path, profile: dict) -> dict:
    brand_dir = safe_path(brand_dir)
    actual = profile_from_dir(brand_dir)
    if profile.get("brand_id") != actual["brand_id"]:
        raise ValueError("Radar brand mismatch")
    profile = actual
    keywords = profile.get("keyword_watch_patterns") or [profile["brand_slug"]]
    if len(keywords) > 10:
        raise ValueError("Limit CT scans to ten keywords per invocation")
    rows, errors, successes = [], [], []
    for keyword in keywords:
        try:
            rows.extend(_fetch_crt_json(keyword)); successes.append(keyword)
        except (ValueError, OSError) as exc:
            errors.append({"keyword": keyword, "error": str(exc)})
    candidates = extract_candidate_domains_from_crt(rows, profile_allowlist(profile), set())
    candidates = [host for host in candidates if any(k.lower() in host for k in keywords)]
    path = brand_dir / "radar_seen.json"
    with locked(brand_dir / ".radar.lock"):
        state = read_json(path) if path.exists() else {"schema_version": 2, "candidates": {}}
        if state.get("schema_version") != 2:
            raise ValueError("Legacy radar state requires reviewed migration; refusing silent reset")
        for host in candidates:
            state["candidates"].setdefault(host, {"status": "PENDING_REVIEW", "first_seen_at": utc_now()})
            state["candidates"][host]["last_seen_at"] = utc_now()
        state.update(last_attempt_at=utc_now(), errors=errors)
        if successes:
            state["last_successful_query_at"] = utc_now()
        atomic_write_json(path, state)
        pending = sorted(host for host, item in state["candidates"].items() if item["status"] == "PENDING_REVIEW" and not is_allowlisted_url(host, profile_allowlist(profile)))
    return {"status": "PARTIAL" if errors and successes else "FAILED" if errors else "OK", "errors": errors,
            "successful_keywords": successes, "pending_domains": pending, "pending_count": len(pending),
            "warning": "CT names and first-seen times are leads, not newly registered or proven infringing domains"}


def triage(brand_dir: Path, domain: str, decision: str, reviewer: str, rationale: str) -> dict:
    if decision not in ("CONFIRMED_FOR_REVIEWED_CASE", "REJECTED", "AUTHORIZED") or not reviewer.strip() or not rationale.strip():
        raise ValueError("Explicit decision, reviewer and rationale required")
    path = safe_path(brand_dir) / "radar_seen.json"
    with locked(brand_dir / ".radar.lock"):
        state = read_json(path)
        entry = state["candidates"][normalize_hostname(domain)]
        entry.update(status=decision, reviewer=reviewer, rationale=rationale, reviewed_at=utc_now())
        atomic_write_json(path, state)
    return entry


def _main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH)
    parser.add_argument("--slug", required=True)
    parser.add_argument("--triage-domain"); parser.add_argument("--decision"); parser.add_argument("--reviewer"); parser.add_argument("--rationale")
    args = parser.parse_args(argv)
    directory, profile = load_brand_profile(args.slug, args.registry)
    result = triage(directory, args.triage_domain, args.decision or "", args.reviewer or "", args.rationale or "") if args.triage_domain else run_radar_scan(directory, profile)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(result.get("status") in ("FAILED", "PARTIAL"))


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr); sys.exit(2)
