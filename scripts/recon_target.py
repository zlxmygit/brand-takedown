"""Append-only evidence captures. Hashes prove consistency, not legal authenticity."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import socket
import ipaddress
import sys
import uuid
from urllib.parse import quote

from brand_registry import (DEFAULT_REGISTRY_PATH, check_target, load_brand_profile,
                            normalize_hostname, profile_allowlist, utc_now)
from case_manager import assert_case_brand, case_profile, load_case, mutate_case
from safe_http import fetch, public_addresses, resolve_addresses
from storage import atomic_write_bytes, atomic_write_json, locked, private_dir, read_json, safe_path

_atomic_write_json = atomic_write_json
_utc_now_iso = utc_now
EXCLUDED_MANIFEST_FILES = {"evidence-manifest.json"}


def extract_storefront_fingerprints(html: str, headers_text: str = "") -> dict:
    """Untrusted leads only: page text cannot establish ownership or infringement."""
    combined = html + "\n" + headers_text
    patterns = {
        "shopify_domains": r"\b[a-z0-9][a-z0-9-]*\.myshopify\.com\b",
        "stripe_publishable_keys": r"\bpk_live_[0-9a-zA-Z]{16,}\b",
        "paypal_client_ids": r"paypal\.com/sdk/js\?[^\"']*client-id=([A-Za-z0-9_-]{12,})",
        "paypal_merchant_ids": r"merchant-id=([A-Z0-9]{8,24})",
        "ga_ids": r"\b(?:G-[A-Z0-9]{6,14}|UA-\d{4,12}-\d{1,4})\b",
        "meta_pixel_ids": r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]",
    }
    result = {key: sorted(set(re.findall(pattern, combined, re.I))) for key, pattern in patterns.items()}
    result["platform_hint"] = "shopify" if result["shopify_domains"] or "cdn.shopify.com" in combined.lower() else "unknown"
    result["confidence"] = "UNVERIFIED_PAGE_CONTROLLED_LEADS"
    result["needs_checkout_probe"] = not any(result[k] for k in ("stripe_publishable_keys", "paypal_client_ids", "paypal_merchant_ids"))
    return result


def query_direct_dns(host: str) -> dict:
    host = normalize_hostname(host)
    if not host:
        raise ValueError("Invalid DNS hostname")
    try:
        rows = resolve_addresses(host, 443)
        a = sorted({ip for ip in rows if ipaddress.ip_address(ip).version == 4})
        aaaa = sorted({ip for ip in rows if ipaddress.ip_address(ip).version == 6})
        return {"A": a, "AAAA": aaaa, "dns_query_ok": bool(a or aaaa),
                "source": "SYSTEM_RECURSIVE_RESOLVER", "authoritative": False, "negative_result_verified": False}
    except OSError as exc:
        return {"A": [], "AAAA": [], "dns_query_ok": False, "source": "SYSTEM_RECURSIVE_RESOLVER",
                "authoritative": False, "negative_result_verified": False, "error": str(exc)}


def query_rdap(host: str) -> dict:
    """Discover authoritative RDAP service from IANA. No unverified WHOIS scraping."""
    host = normalize_hostname(host)
    if not host:
        raise ValueError("Invalid RDAP domain")
    try:
        bootstrap = fetch("https://data.iana.org/rdap/dns.json", max_bytes=2 * 1024 * 1024)
        if bootstrap.status != 200:
            raise ValueError("IANA bootstrap unavailable")
        service = next(url for zones, urls in json.loads(bootstrap.body)["services"] if host.split(".")[-1] in zones for url in urls if url.startswith("https://"))
        response = fetch(service.rstrip("/") + "/domain/" + quote(host, safe=""))
        if response.status != 200:
            raise ValueError(f"RDAP HTTP {response.status}; subdomains may require manual registered-domain lookup")
        document = json.loads(response.body)
        if not isinstance(document, dict) or document.get("objectClassName") != "domain":
            raise ValueError("Invalid RDAP domain response")
        return {"ok": True, "source": response.url, "queried_domain": host, "document": document,
                "use": "REGISTRATION_HINT_NOT_PROOF_OF_ABUSE"}
    except (ValueError, OSError, StopIteration, KeyError, TypeError) as exc:
        return {"ok": False, "queried_domain": host, "error": str(exc), "manual_lookup_required": True}


def _entries(directory: Path) -> list[dict]:
    directory = safe_path(directory)
    result = []
    for path in sorted(directory.rglob("*")):
        safe_path(path)  # Reject all symlinks, including nested directories.
        if path.is_dir():
            continue
        relative = path.relative_to(directory).as_posix()
        if relative in EXCLUDED_MANIFEST_FILES or path.name == ".evidence.lock":
            continue
        if not path.is_file():
            raise ValueError("Special files are not permitted in evidence")
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk); size += len(chunk)
        result.append({"filename": relative, "size_bytes": size, "sha256": digest.hexdigest()})
    return result


def verify_manifest(directory: Path) -> dict:
    directory = safe_path(directory)
    manifest = read_json(directory / "evidence-manifest.json")
    if manifest.get("files") != _entries(directory):
        raise ValueError("EVIDENCE INTEGRITY FAILURE: changed, missing or unsealed files")
    return manifest


def build_evidence_manifest(evidence_dir: Path, target_url: str, direct_dns_ips: list[str], proxy_used: bool) -> dict:
    evidence_dir = private_dir(evidence_dir)
    with locked(evidence_dir / ".evidence.lock"):
        if (evidence_dir / "evidence-manifest.json").exists():
            return verify_manifest(evidence_dir)
        entries = _entries(evidence_dir)
        if not entries:
            raise ValueError("Cannot seal an empty capture")
        manifest = {"schema_version": 2, "capture_id": evidence_dir.name, "target_url": target_url,
                    "captured_at_utc": utc_now(), "direct_dns_ips": direct_dns_ips,
                    "http_fetch_used_proxy": bool(proxy_used), "files": entries}
        atomic_write_json(evidence_dir / "evidence-manifest.json", manifest)
        return manifest


def verify_capture(case_dir: Path, capture_id: str) -> dict:
    data = load_case(case_dir)
    record = next((r for r in data["captures"] if r["capture_id"] == capture_id), None)
    if record is None:
        raise ValueError("Capture does not belong to this case")
    directory = safe_path(case_dir) / "evidence" / capture_id
    manifest_path = directory / "evidence-manifest.json"
    if hashlib.sha256(safe_path(manifest_path).read_bytes()).hexdigest() != record["manifest_sha256"]:
        raise ValueError("Manifest digest differs from the case's original seal")
    return verify_manifest(directory)


def refresh_case_manifest(case_dir: Path) -> dict:
    # Legacy command is verification-only. Never reseal modified historical bytes.
    data = load_case(case_dir)
    manifests = [verify_capture(case_dir, c["capture_id"]) for c in data["captures"]]
    if not manifests:
        raise ValueError("No sealed captures")
    return {"verified": True, "captures": manifests}


def run_recon(target_url: str, case_dir: Path, allowlist_domains=None, proxy=None, referer=None) -> dict:
    data = load_case(case_dir)
    profile = case_profile(case_dir)
    url = check_target(target_url, profile)
    if url not in data["target_urls"]:
        raise ValueError("Target URL is not registered in this case")
    allow = sorted(set(profile_allowlist(profile) + list(allowlist_domains or [])))
    if proxy or referer:
        raise ValueError("Proxy/referer paths are disabled until an enforceable egress adapter exists")
    directory = safe_path(case_dir) / "evidence" / ("CAP-" + uuid.uuid4().hex)
    directory.mkdir(mode=0o700, exist_ok=False)
    host = normalize_hostname(url)
    dns = query_direct_dns(host)
    rdap = query_rdap(host)
    started = utc_now()
    report = {"target_url": url, "capture_id": directory.name, "started_at_utc": started,
              "dns": dns, "rdap": rdap, "capture_status": "FAILED", "trusted_as_instructions": False}
    try:
        response = fetch(url, allow, proxy=proxy, referer=referer)
        atomic_write_bytes(directory / "raw.bin", response.body)
        atomic_write_json(directory / "headers.json", response.headers)
        report.update(final_url=response.url, http_status=response.status, peer_ip=response.peer_ip,
                      redirect_hops=response.hops, tls_sha256=response.tls_sha256,
                      fingerprints=extract_storefront_fingerprints(response.body.decode("utf-8", errors="replace")))
        report["capture_status"] = "CAPTURED" if 200 <= response.status < 300 and response.body else "PARTIAL"
    except (ValueError, OSError) as exc:
        report["error"] = str(exc)
    report["finished_at_utc"] = utc_now()
    atomic_write_json(directory / "recon-report.json", report)
    manifest = build_evidence_manifest(directory, url, dns.get("A", []) + dns.get("AAAA", []), False)
    seal = hashlib.sha256((directory / "evidence-manifest.json").read_bytes()).hexdigest()
    def record(case):
        case["captures"].append({"capture_id": directory.name, "target_url": url, "status": report["capture_status"],
                                 "manifest_sha256": seal, "captured_at_utc": manifest["captured_at_utc"]})
        if report["capture_status"] == "CAPTURED" and case["status"] == "DISCOVERED":
            case["status"] = "EVIDENCE_LOCKED"
        if report.get("peer_ip") and not case["infrastructure_baseline"].get("ips"):
            case["infrastructure_baseline"]["ips"] = [report["peer_ip"]]
    mutate_case(case_dir, "capture_recorded", record)
    return report


def add_evidence(case_dir: Path, target_url: str, source: Path) -> dict:
    """Attach a user-reviewed screenshot/document as a NEW capture, never edit one."""
    data = load_case(case_dir)
    target = check_target(target_url, case_profile(case_dir))
    if target not in data["target_urls"]:
        raise ValueError("Unknown case target")
    source = safe_path(source)
    if not source.is_file() or source.stat().st_size > 25 * 1024 * 1024:
        raise ValueError("Evidence must be a regular file up to 25 MiB")
    if source.name in ("evidence-manifest.json", ".evidence.lock", "recon-report.json", "headers.json"):
        raise ValueError("Reserved evidence metadata filename")
    with source.open("rb") as stream:
        content = stream.read(25 * 1024 * 1024 + 1)
    if not content or len(content) > 25 * 1024 * 1024:
        raise ValueError("Evidence is empty or exceeds the size budget")
    directory = safe_path(case_dir) / "evidence" / ("CAP-" + uuid.uuid4().hex)
    directory.mkdir(mode=0o700, exist_ok=False)
    atomic_write_bytes(directory / source.name, content)
    manifest = build_evidence_manifest(directory, target, [], False)
    def record(case):
        case["captures"].append({"capture_id": directory.name, "target_url": target, "status": "USER_SUPPLIED",
            "manifest_sha256": hashlib.sha256((directory / "evidence-manifest.json").read_bytes()).hexdigest(),
            "captured_at_utc": manifest["captured_at_utc"]})
    mutate_case(case_dir, "user_evidence_added", record)
    return manifest


def trigger_wayback_save(target_url: str, allowlist_domains=None) -> dict:
    raise ValueError("Automatic public archiving disabled: explicit external publication review required")


def _main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("run", "refresh-manifest", "add-evidence", "archive-wayback"):
        p = sub.add_parser(name)
        p.add_argument("--slug", required=True); p.add_argument("--case-dir", type=Path, required=True)
        if name in ("run", "add-evidence", "archive-wayback"):
            p.add_argument("--url", required=True)
        if name == "run":
            p.add_argument("--proxy"); p.add_argument("--referer")
        if name == "add-evidence":
            p.add_argument("--source", type=Path, required=True)
    args = parser.parse_args(argv)
    brand_dir, _ = load_brand_profile(args.slug, args.registry)
    assert_case_brand(args.case_dir, brand_dir)
    if args.cmd == "run":
        result = run_recon(args.url, args.case_dir, proxy=args.proxy, referer=args.referer)
    elif args.cmd == "add-evidence":
        result = add_evidence(args.case_dir, args.url, args.source)
    elif args.cmd == "archive-wayback":
        result = trigger_wayback_save(args.url)
    else:
        result = refresh_case_manifest(args.case_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(result.get("capture_status") in ("FAILED", "PARTIAL"))


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr); sys.exit(2)
