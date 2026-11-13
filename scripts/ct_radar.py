"""CT search and offline lookalike permutation radar with explicit errors and human triage."""
from __future__ import annotations

import argparse
import ipaddress
from collections import deque
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import quote

from brand_registry import (DEFAULT_REGISTRY_PATH, is_allowlisted_url,
                            load_brand_profile, normalize_hostname, profile_allowlist, profile_from_dir, utc_now)
from safe_http import fetch
from domain_names import registrable_domain
from dns_json import dns_answers
from storage import atomic_write_json, locked, read_json, safe_path

MAX_RADAR_CANDIDATES = 10000
MAX_NEW_PER_SCAN = 2000

COMMON_LOOKALIKE_TLDS = ("com", "shop", "store", "net", "org", "co")
HOMOGLYPH_SUBS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "m": "rn", "w": "vv"}
COMBO_PREFIXES = ("shop", "official", "buy", "support")
COMBO_SUFFIXES = ("shop", "store", "official", "outlet", "support")



def _split_domain_label_and_suffix(domain: str) -> tuple[str, str]:
    registered = registrable_domain(domain)
    return tuple(registered.split(".", 1)) if registered else ("", "")


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
                               extra_tlds: tuple[str, ...] = (), max_variants: int = 60,
                               offset: int = 0) -> list[dict]:
    """Interleave source domains and mutation types; offset rotates across scans."""
    if max_variants < 1:
        return []
    if len(official_domains) > 50 or len(extra_tlds) > 10:
        raise ValueError("Lookalike generation supports up to 50 source domains and ten extra suffixes")
    by_source = []
    seen_sources = set()
    for raw in official_domains:
        label, suffix = _split_domain_label_and_suffix(raw)
        if not label or (label, suffix) in seen_sources:
            continue
        seen_sources.add((label, suffix))
        tlds = tuple(dict.fromkeys((suffix,) + (() if suffix == "example" else COMMON_LOOKALIKE_TLDS) + tuple(extra_tlds)))
        groups = {}
        for mutated, kind in _label_permutations(label):
            groups.setdefault(kind, deque())
            for tld in tlds:
                host = normalize_hostname(f"{mutated}.{tld}")
                if host and not is_allowlisted_url(host, allowlist_domains):
                    groups[kind].append({"domain": host, "mutation_kind": kind, "source_domain": normalize_hostname(raw)})
        by_source.append(groups)
    # Kind-major interleaving covers every source before revisiting one source.
    kinds = list(dict.fromkeys(kind for groups in by_source for kind in groups))
    queues = deque(groups[kind] for kind in kinds for groups in by_source if groups.get(kind))
    pool, seen = [], set()
    while queues:
        group = queues.popleft()
        item = group.popleft()
        if item["domain"] not in seen:
            seen.add(item["domain"])
            pool.append(item)
        if group:
            queues.append(group)
    if not pool:
        return []
    offset %= len(pool)
    return [pool[(offset + i) % len(pool)] for i in range(min(max_variants, len(pool)))]



def _query_doh_rr(domain: str, rrtype: str) -> list[str]:
    rr_code = {"A": 1, "MX": 15}[rrtype]
    response = fetch(f"https://dns.google/resolve?name={quote(domain, safe='')}&type={rrtype}", max_bytes=65536)
    if response.status != 200:
        raise ValueError(f"DoH {rrtype} HTTP {response.status}")
    values = []
    for ans in dns_answers(json.loads(response.body), domain, rr_code):
        raw = ans["data"].strip()
        if rrtype == "A":
            try:
                ip_obj = ipaddress.IPv4Address(raw)
            except ValueError as exc:
                raise ValueError("Invalid DNS A address") from exc
            if ip_obj.is_global and not ip_obj.is_multicast:
                values.append(str(ip_obj))
        else:
            parts = raw.split()
            if len(parts) != 2 or not parts[0].isdigit() or not 0 <= int(parts[0]) <= 65535:
                raise ValueError("Invalid MX preference/exchange")
            if parts == ["0", "."]:  # RFC 7505: the domain explicitly accepts no mail.
                continue
            exchange = normalize_hostname(parts[1])
            if not exchange:
                raise ValueError("Invalid MX exchange")
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
    successful_types = []
    for rrtype, bucket in (("A", a_records), ("MX", mx_records)):
        try:
            bucket.extend(_query_doh_rr(host, rrtype))
            successful_types.append(rrtype)
        except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError) as exc:
            errors.append(f"{rrtype}: {exc}")
    return {
        "domain": host,
        "a_records": a_records,
        "mx_records": mx_records,
        "live_dns": bool(a_records or mx_records),
        "errors": errors,
        "successful_types": successful_types,
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
        except (ValueError, OSError, TypeError, AttributeError, RecursionError) as exc:
            errors.append({"keyword": keyword, "error": str(exc)})
    candidates = extract_candidate_domains_from_crt(rows, allowlist, set())
    candidates = [host for host in candidates if any(k.lower() in host for k in keywords)]
    path = brand_dir / "radar_seen.json"
    seed = hashlib.sha256(json.dumps([profile["official_domains"], allowlist], sort_keys=True).encode()).hexdigest()
    with locked(brand_dir / ".radar.lock"):
        initial = read_json(path) if path.exists() else {}
        offset = initial.get("lookalike_cursor", 0) if initial.get("lookalike_seed") == seed else 0
        if type(offset) is not int or offset < 0:
            raise ValueError("Invalid lookalike scan cursor")
    live_lookalikes: list[dict] = []
    lookalike_probes_ok = 0
    lookalike_checked = 0
    if include_lookalikes:
        capped = max(1, min(int(lookalike_limit), 60))
        for item in generate_lookalike_domains(profile["official_domains"], allowlist, max_variants=capped, offset=offset):
            lookalike_checked += 1
            probe = probe_domain_dns_signals(item["domain"])
            if probe["live_dns"]:
                live_lookalikes.append({**item, "a_records": probe["a_records"], "mx_records": probe["mx_records"]})
            if probe.get("successful_types") or probe["live_dns"] or not probe["errors"]:
                lookalike_probes_ok += 1
            if probe["errors"]:
                errors.append({"lookalike": item["domain"], "error": "; ".join(probe["errors"])})
    path = brand_dir / "radar_seen.json"
    with locked(brand_dir / ".radar.lock"):
        state = read_json(path) if path.exists() else {"schema_version": 2, "candidates": {}}
        if state.get("schema_version") != 2:
            raise ValueError("Legacy radar state requires reviewed migration; refusing silent reset")
        if not isinstance(state.get("candidates"), dict):
            raise ValueError("Invalid radar candidates")
        now = utc_now()
        admitted = deferred = 0
        def entry_for(host):
            nonlocal admitted, deferred
            if host in state["candidates"]:
                return state["candidates"][host]
            if len(state["candidates"]) >= MAX_RADAR_CANDIDATES or admitted >= MAX_NEW_PER_SCAN:
                deferred += 1
                return None
            admitted += 1
            entry = {"status": "PENDING_REVIEW", "first_seen_at": now}
            state["candidates"][host] = entry
            return entry
        for host in candidates:
            entry = entry_for(host)
            if entry is not None:
                entry["last_seen_at"] = now
        for item in live_lookalikes:
            entry = entry_for(item["domain"])
            if entry is None:
                continue
            entry["last_seen_at"] = now
            entry["source"] = "LOOKALIKE_DNS"
            entry["mutation_kind"] = item["mutation_kind"]
            entry["dns_a"] = item["a_records"]
            entry["dns_mx"] = item["mx_records"]
        if deferred:
            errors.append({"kind": "CAPACITY_LIMIT", "deferred_count": deferred,
                           "error": "Candidate capacity reached; existing candidates retained. Export and archive reviewed candidates before continuing."})
        if include_lookalikes and (state.get("lookalike_seed") != seed or state.get("lookalike_cursor", 0) == offset):
            state["lookalike_seed"] = seed
            state["lookalike_cursor"] = offset + lookalike_checked
        state.update(last_attempt_at=now, errors=errors)
        if (successes or lookalike_probes_ok) and not errors:
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
    if len(reviewer) > 200 or len(rationale) > 4000:
        raise ValueError("Reviewer or rationale exceeds length limit")
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
