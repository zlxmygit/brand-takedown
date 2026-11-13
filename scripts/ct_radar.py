"""CT search and offline lookalike permutation radar with explicit errors and human triage."""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import sys
from urllib.parse import quote

from brand_registry import (COMMON_SECOND_LEVEL_PUBLIC_SUFFIXES, DEFAULT_REGISTRY_PATH, is_allowlisted_url,
                            load_brand_profile, normalize_hostname, profile_allowlist, profile_from_dir, utc_now)
from safe_http import fetch
from storage import atomic_write_json, locked, read_json, safe_path

COMMON_LOOKALIKE_TLDS = ("com", "shop", "store", "net", "org", "co")
HOMOGLYPH_SUBS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "m": "rn", "w": "vv"}
COMBO_PREFIXES = ("shop", "official", "buy", "support")
COMBO_SUFFIXES = ("shop", "store", "official", "outlet", "support")


def _split_domain_label_and_suffix(domain: str) -> tuple[str, str]:
    clean = normalize_hostname(domain)
    if not clean or "." not in clean:
        return "", ""
    labels = clean.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in COMMON_SECOND_LEVEL_PUBLIC_SUFFIXES:
        return labels[-3], ".".join(labels[-2:])
    return labels[-2], labels[-1]


def _label_permutations(label: str) -> list[tuple[str, str]]:
    """Generate deterministic typo/hyphen/ASCII-homoglyph/combosquat label candidates."""
    out: list[tuple[str, str]] = []
    if len(label) >= 4:
        for i in range(len(label)):
            out.append((label[:i] + label[i + 1:], "omission"))
    for i in range(len(label) - 1):
        if label[i] != label[i + 1]:
            out.append((label[:i] + label[i + 1] + label[i] + label[i + 2:], "transposition"))
    for i in range(len(label)):
        out.append((label[:i + 1] + label[i:], "repetition"))
    if "-" in label:
        out.append((label.replace("-", ""), "hyphenation"))
    else:
        for i in range(1, len(label)):
            out.append((label[:i] + "-" + label[i:], "hyphenation"))
    for idx, ch in enumerate(label):
        if ch in HOMOGLYPH_SUBS:
            out.append((label[:idx] + HOMOGLYPH_SUBS[ch] + label[idx + 1:], "homoglyph_ascii"))
    for src, dst in (("rn", "m"), ("vv", "w")):
        pos = label.find(src)
        if pos != -1:
            out.append((label[:pos] + dst + label[pos + len(src):], "homoglyph_ascii"))
    for prefix in COMBO_PREFIXES:
        out.append((f"{prefix}-{label}", "combosquatting"))
    for suffix in COMBO_SUFFIXES:
        out.append((f"{label}-{suffix}", "combosquatting"))
    return out


def generate_lookalike_domains(official_domains: list[str], allowlist_domains: list[str], *,
                               extra_tlds: tuple[str, ...] = (), max_variants: int = 60) -> list[dict]:
    """Build bounded offline lookalike domain candidates excluded from the brand allowlist."""
    if max_variants < 1:
        return []
    candidates: list[dict] = []
    seen: set[str] = set()
    for raw in official_domains:
        label, base_tld = _split_domain_label_and_suffix(raw)
        if not label or not base_tld:
            continue
        tlds = ("example",) + tuple(extra_tlds) if base_tld == "example" else tuple(
            dict.fromkeys((base_tld,) + COMMON_LOOKALIKE_TLDS + tuple(extra_tlds))
        )
        for mutated, kind in _label_permutations(label):
            for tld in tlds:
                host = normalize_hostname(f"{mutated}.{tld}")
                if not host or host in seen or is_allowlisted_url(host, allowlist_domains):
                    continue
                seen.add(host)
                candidates.append({"domain": host, "mutation_kind": kind, "source_domain": normalize_hostname(raw)})
                if len(candidates) >= max_variants:
                    return candidates
    return candidates


def _query_doh_rr(domain: str, rrtype: str) -> list[str]:
    rr_code = {"A": 1, "MX": 15}[rrtype]
    response = fetch(f"https://dns.google/resolve?name={quote(domain, safe='')}&type={rrtype}", max_bytes=65536)
    if response.status != 200:
        raise ValueError(f"DoH {rrtype} HTTP {response.status}")
    payload = json.loads(response.body)
    if not isinstance(payload, dict):
        raise ValueError(f"Invalid DoH {rrtype} response")
    values: list[str] = []
    for ans in payload.get("Answer", []) or []:
        if not isinstance(ans, dict) or ans.get("type") != rr_code:
            continue
        raw = str(ans.get("data", "")).strip()
        if rrtype == "A":
            try:
                ip_obj = ipaddress.ip_address(raw)
                if ip_obj.is_global and not ip_obj.is_multicast:
                    values.append(str(ip_obj))
            except ValueError:
                continue
        elif rrtype == "MX":
            parts = raw.split()
            exchange = normalize_hostname(parts[-1] if parts else "")
            if exchange:
                values.append(exchange)
    return list(dict.fromkeys(values))


def probe_domain_dns_signals(domain: str) -> dict:
    """Probe non-authoritative DNS A and MX presence via bounded HTTPS DoH."""
    host = normalize_hostname(domain)
    if not host:
        raise ValueError("Invalid candidate domain")
    a_records: list[str] = []
    mx_records: list[str] = []
    errors: list[str] = []
    for rrtype, bucket in (("A", a_records), ("MX", mx_records)):
        try:
            bucket.extend(_query_doh_rr(host, rrtype))
        except (ValueError, OSError, KeyError, TypeError) as exc:
            errors.append(f"{rrtype}: {exc}")
    return {
        "domain": host,
        "a_records": a_records,
        "mx_records": mx_records,
        "live_dns": bool(a_records or mx_records),
        "errors": errors,
        "authoritative": False,
        "use": "UNVERIFIED_DNS_LEAD",
    }


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


def run_radar_scan(brand_dir: Path, profile: dict, *, include_lookalikes: bool = False, lookalike_limit: int = 20) -> dict:
    brand_dir = safe_path(brand_dir)
    actual = profile_from_dir(brand_dir)
    if profile.get("brand_id") != actual["brand_id"]:
        raise ValueError("Radar brand mismatch")
    profile = actual
    allowlist = profile_allowlist(profile)
    keywords = profile.get("keyword_watch_patterns") or [profile["brand_slug"]]
    if len(keywords) > 10:
        raise ValueError("Limit CT scans to ten keywords per invocation")
    rows, errors, successes = [], [], []
    for keyword in keywords:
        try:
            rows.extend(_fetch_crt_json(keyword)); successes.append(keyword)
        except (ValueError, OSError) as exc:
            errors.append({"keyword": keyword, "error": str(exc)})
    candidates = extract_candidate_domains_from_crt(rows, allowlist, set())
    candidates = [host for host in candidates if any(k.lower() in host for k in keywords)]
    live_lookalikes: list[dict] = []
    lookalike_probes_ok = 0
    lookalike_checked = 0
    if include_lookalikes:
        capped = max(1, min(int(lookalike_limit), 60))
        for item in generate_lookalike_domains(profile["official_domains"], allowlist, max_variants=capped):
            lookalike_checked += 1
            probe = probe_domain_dns_signals(item["domain"])
            if probe["live_dns"]:
                live_lookalikes.append({**item, "a_records": probe["a_records"], "mx_records": probe["mx_records"]})
                lookalike_probes_ok += 1
            elif probe["errors"]:
                errors.append({"lookalike": item["domain"], "error": "; ".join(probe["errors"])})
            else:
                lookalike_probes_ok += 1
    path = brand_dir / "radar_seen.json"
    with locked(brand_dir / ".radar.lock"):
        state = read_json(path) if path.exists() else {"schema_version": 2, "candidates": {}}
        if state.get("schema_version") != 2:
            raise ValueError("Legacy radar state requires reviewed migration; refusing silent reset")
        now = utc_now()
        for host in candidates:
            entry = state["candidates"].setdefault(host, {"status": "PENDING_REVIEW", "first_seen_at": now})
            entry["last_seen_at"] = now
        for item in live_lookalikes:
            entry = state["candidates"].setdefault(item["domain"], {"status": "PENDING_REVIEW", "first_seen_at": now})
            entry["last_seen_at"] = now
            entry["source"] = "LOOKALIKE_DNS"
            entry["mutation_kind"] = item["mutation_kind"]
            entry["dns_a"] = item["a_records"]
            entry["dns_mx"] = item["mx_records"]
        state.update(last_attempt_at=now, errors=errors)
        if successes or lookalike_probes_ok:
            state["last_successful_query_at"] = now
        atomic_write_json(path, state)
        pending = sorted(host for host, item in state["candidates"].items() if item["status"] == "PENDING_REVIEW" and not is_allowlisted_url(host, allowlist))
    any_success = bool(successes or lookalike_probes_ok)
    result = {
        "status": "PARTIAL" if errors and any_success else "FAILED" if errors else "OK",
        "errors": errors,
        "successful_keywords": successes,
        "pending_domains": pending,
        "pending_count": len(pending),
        "warning": "CT names, lookalike permutations and DNS A/MX leads are unverified signals, not newly registered or proven infringing domains",
    }
    if include_lookalikes:
        result["lookalike_summary"] = {
            "checked_count": lookalike_checked,
            "live_count": len(live_lookalikes),
            "live_domains": live_lookalikes,
        }
    return result


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
    parser.add_argument("--include-lookalikes", action="store_true", help="Also generate bounded lookalike permutations and check DoH DNS A/MX signals")
    parser.add_argument("--lookalike-limit", type=int, default=20, help="Maximum lookalike permutations to screen per run (1-60)")
    parser.add_argument("--triage-domain"); parser.add_argument("--decision"); parser.add_argument("--reviewer"); parser.add_argument("--rationale")
    args = parser.parse_args(argv)
    directory, profile = load_brand_profile(args.slug, args.registry)
    result = (
        triage(directory, args.triage_domain, args.decision or "", args.reviewer or "", args.rationale or "")
        if args.triage_domain
        else run_radar_scan(directory, profile, include_lookalikes=args.include_lookalikes, lookalike_limit=args.lookalike_limit)
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(result.get("status") in ("FAILED", "PARTIAL"))


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr); sys.exit(2)
