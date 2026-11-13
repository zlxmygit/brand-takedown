"""Append-only evidence captures. Hashes prove consistency, not legal authenticity."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
import uuid
from urllib.parse import quote

from brand_registry import (COMMON_SECOND_LEVEL_PUBLIC_SUFFIXES, DEFAULT_REGISTRY_PATH, check_target, load_brand_profile,
                            normalize_hostname, profile_allowlist, utc_now)
from case_manager import assert_case_brand, case_profile, load_case, mutate_case
from safe_http import fetch, resolve_addresses
from storage import atomic_write_bytes, atomic_write_json, locked, private_dir, read_json, safe_path

_atomic_write_json = atomic_write_json
_utc_now_iso = utc_now
EXCLUDED_MANIFEST_FILES = {"evidence-manifest.json"}
_EMAIL_RE = re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24})\b")


def _dedup_preserve(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        val = item.strip()
        if val and val not in seen:
            seen.add(val)
            out.append(val)
    return out


def _is_global_public_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    transition = isinstance(ip_obj, ipaddress.IPv6Address) and (
        ip_obj.ipv4_mapped is not None or ip_obj.sixtofour is not None or ip_obj.teredo is not None
        or ip_obj in ipaddress.ip_network("64:ff9b::/96") or ip_obj in ipaddress.ip_network("64:ff9b:1::/48")
    )
    return bool(ip_obj.is_global and not ip_obj.is_multicast and not ip_obj.is_unspecified and not transition)


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


def _extract_vcard_field(vcard_array: object, field_name: str) -> list[str]:
    values: list[str] = []
    if not isinstance(vcard_array, list) or len(vcard_array) < 2 or not isinstance(vcard_array[1], list):
        return values
    target = field_name.lower()
    for prop in vcard_array[1]:
        if not isinstance(prop, list) or len(prop) < 4 or str(prop[0]).lower() != target:
            continue
        val = prop[3]
        if isinstance(val, str) and val.strip():
            values.append(val.strip())
        elif isinstance(val, list):
            joined = " ".join(str(x).strip() for x in val if str(x).strip())
            if joined:
                values.append(joined)
    return values


def _walk_rdap_entities(entities: object, inherited_roles: tuple[str, ...] = ()) -> list[tuple[tuple[str, ...], dict]]:
    out: list[tuple[tuple[str, ...], dict]] = []
    if not isinstance(entities, list):
        return out
    for ent in entities:
        if not isinstance(ent, dict):
            continue
        own_roles = tuple(str(r).lower() for r in ent.get("roles", []) if str(r).strip())
        roles = own_roles or inherited_roles
        out.append((roles, ent))
        if isinstance(ent.get("entities"), list):
            out.extend(_walk_rdap_entities(ent.get("entities"), roles))
    return out


def parse_rdap_domain_json(payload: dict) -> dict:
    """Extract untrusted registration hints from a domain RDAP JSON response."""
    if not isinstance(payload, dict) or not payload:
        return {"rdap_available": False, "ldh_name": "", "registrar": "", "registrar_iana_id": "",
                "creation_date": "", "expiration_date": "", "abuse_emails": [], "abuse_phones": [],
                "name_servers": [], "status_codes": []}
    registrar = iana_id = ""
    abuse_emails: list[str] = []
    abuse_phones: list[str] = []
    for roles, ent in _walk_rdap_entities(payload.get("entities")):
        vcard = ent.get("vcardArray")
        fns = _extract_vcard_field(vcard, "fn") or _extract_vcard_field(vcard, "org")
        if "registrar" in roles and fns and not registrar:
            registrar = fns[0]
        if "registrar" in roles and not iana_id:
            for pid in ent.get("publicIds", []) or []:
                if isinstance(pid, dict) and "iana" in str(pid.get("type", "")).lower():
                    ident = str(pid.get("identifier", "")).strip()
                    if ident:
                        iana_id = ident
                        break
        if "abuse" in roles:
            for raw_em in _extract_vcard_field(vcard, "email"):
                abuse_emails.extend(em.lower() for em in _EMAIL_RE.findall(raw_em.replace("mailto:", "")))
            for raw_tel in _extract_vcard_field(vcard, "tel"):
                tel_clean = raw_tel.replace("tel:", "").strip()
                if tel_clean:
                    abuse_phones.append(tel_clean)
    creation_date = expiration_date = ""
    for ev in payload.get("events", []) or []:
        if not isinstance(ev, dict):
            continue
        action = str(ev.get("eventAction", "")).lower()
        date_val = str(ev.get("eventDate", "")).strip()
        if not date_val:
            continue
        if action in ("registration", "registered") and not creation_date:
            creation_date = date_val
        elif action in ("expiration", "soft expiration") and not expiration_date:
            expiration_date = date_val
    name_servers = [
        str(ns.get("ldhName") or ns.get("unicodeName") or "").strip().lower().rstrip(".")
        for ns in (payload.get("nameservers", []) or [])
        if isinstance(ns, dict) and str(ns.get("ldhName") or ns.get("unicodeName") or "").strip()
    ]
    status_codes = [str(s).strip().lower().replace(" ", "") for s in (payload.get("status", []) or []) if str(s).strip()]
    return {
        "rdap_available": True,
        "ldh_name": str(payload.get("ldhName") or "").strip().lower(),
        "registrar": registrar,
        "registrar_iana_id": iana_id,
        "creation_date": creation_date,
        "expiration_date": expiration_date,
        "abuse_emails": _dedup_preserve(abuse_emails),
        "abuse_phones": _dedup_preserve(abuse_phones),
        "name_servers": _dedup_preserve(name_servers),
        "status_codes": _dedup_preserve(status_codes),
    }


def parse_rdap_ip_json(payload: dict, queried_ip: str = "") -> dict:
    """Extract untrusted hosting/ASN hints from an IP network RDAP JSON response."""
    if not isinstance(payload, dict) or not payload:
        return {}
    holder = ""
    abuse_emails: list[str] = []
    fallback_emails: list[str] = []
    for roles, ent in _walk_rdap_entities(payload.get("entities")):
        vcard = ent.get("vcardArray")
        fns = _extract_vcard_field(vcard, "fn") or _extract_vcard_field(vcard, "org")
        if fns and not holder and any(r in roles for r in ("registrant", "administrative", "technical", "noc")):
            holder = fns[0]
        elif fns and not holder:
            holder = fns[0]
        for raw_em in _extract_vcard_field(vcard, "email"):
            for em in _EMAIL_RE.findall(raw_em.replace("mailto:", "")):
                (abuse_emails if ("abuse" in roles or "abuse" in em.lower()) else fallback_emails).append(em.lower())
    asns = [f"AS{str(a).lstrip('ASas')}" for a in (payload.get("arin_originas0_originautnums", []) or []) if str(a).strip()]
    for remark in payload.get("remarks", []) or []:
        if isinstance(remark, dict):
            for desc in remark.get("description", []) or []:
                asns.extend(m.upper() for m in re.findall(r"\bAS\d{2,10}\b", str(desc), re.IGNORECASE))
    cidrs = [
        f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
        for c in (payload.get("cidr0_cidrs", []) or [])
        if isinstance(c, dict) and (c.get("v4prefix") or c.get("v6prefix")) and c.get("length") is not None
    ]
    return {
        "ip": queried_ip or str(payload.get("startAddress", "")).strip(),
        "handle": str(payload.get("handle", "")).strip(),
        "network_name": str(payload.get("name", "")).strip(),
        "country": str(payload.get("country", "")).strip().upper(),
        "holder": holder,
        "cidrs": _dedup_preserve(cidrs),
        "asns": _dedup_preserve(asns),
        "abuse_emails": _dedup_preserve(abuse_emails or fallback_emails),
    }


def domain_rdap_candidates(host: str) -> list[str]:
    """Generate ordered domain candidates from exact hostname up to registrable parent."""
    clean = normalize_hostname(host)
    if not clean or "." not in clean:
        return []
    labels = clean.split(".")
    candidates: list[str] = []
    for idx in range(0, max(1, len(labels) - 1)):
        sub = ".".join(labels[idx:])
        if "." in sub and sub not in COMMON_SECOND_LEVEL_PUBLIC_SUFFIXES:
            candidates.append(sub)
    return candidates


def _find_domain_rdap_service(bootstrap_doc: dict, domain: str) -> str:
    services = bootstrap_doc.get("services") if isinstance(bootstrap_doc, dict) else None
    if not isinstance(services, list):
        raise ValueError("Invalid IANA DNS RDAP bootstrap format")
    tld = domain.split(".")[-1]
    return next(
        url for zones, urls in services
        if isinstance(zones, list) and tld in zones and isinstance(urls, list)
        for url in urls if isinstance(url, str) and url.startswith("https://")
    )


def _find_ip_rdap_service(bootstrap_doc: dict, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    services = bootstrap_doc.get("services") if isinstance(bootstrap_doc, dict) else None
    if not isinstance(services, list):
        raise ValueError("Invalid IANA IP RDAP bootstrap format")
    best_prefix = -1
    best_url = ""
    for cidrs, urls in services:
        if not isinstance(cidrs, list) or not isinstance(urls, list):
            continue
        https_url = next((u for u in urls if isinstance(u, str) and u.startswith("https://")), "")
        if not https_url:
            continue
        for raw_cidr in cidrs:
            try:
                net = ipaddress.ip_network(str(raw_cidr), strict=False)
            except ValueError:
                continue
            if net.version == ip_obj.version and ip_obj in net and net.prefixlen > best_prefix:
                best_prefix = net.prefixlen
                best_url = https_url
    if not best_url:
        raise ValueError("No matching authoritative RIR RDAP service")
    return best_url


def query_rdap(host: str) -> dict:
    """Discover authoritative RDAP service from IANA with parent-domain fallback."""
    host = normalize_hostname(host)
    if not host:
        raise ValueError("Invalid RDAP domain")
    candidates = domain_rdap_candidates(host)
    if not candidates:
        return {"ok": False, "requested_host": host, "queried_domain": host,
                "error": "No registrable RDAP candidate", "manual_lookup_required": True}
    try:
        bootstrap = fetch("https://data.iana.org/rdap/dns.json", max_bytes=2 * 1024 * 1024)
        if bootstrap.status != 200:
            raise ValueError("IANA bootstrap unavailable")
        bootstrap_doc = json.loads(bootstrap.body)
        if not isinstance(bootstrap_doc, dict) or not isinstance(bootstrap_doc.get("services"), list):
            raise ValueError("Invalid IANA RDAP bootstrap document")
        last_error = "No matching authoritative RDAP service"
        for candidate in candidates:
            try:
                service = _find_domain_rdap_service(bootstrap_doc, candidate)
            except StopIteration:
                last_error = f"No authoritative RDAP service for {candidate}"
                continue
            response = fetch(service.rstrip("/") + "/domain/" + quote(candidate, safe=""))
            if response.status != 200:
                last_error = f"RDAP HTTP {response.status} for {candidate}"
                continue
            document = json.loads(response.body)
            if not isinstance(document, dict) or document.get("errorCode") or document.get("objectClassName") != "domain":
                last_error = f"Invalid RDAP domain response for {candidate}"
                continue
            return {
                "ok": True,
                "source": response.url,
                "requested_host": host,
                "queried_domain": candidate,
                "document": document,
                "summary": parse_rdap_domain_json(document),
                "use": "REGISTRATION_HINT_NOT_PROOF_OF_ABUSE",
            }
        raise ValueError(f"{last_error}; subdomains may require manual registered-domain lookup")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        return {"ok": False, "requested_host": host, "queried_domain": host, "error": str(exc), "manual_lookup_required": True}


def _parse_cymru_txt_record(txt_line: str) -> dict:
    cleaned = (txt_line or "").strip().strip('"')
    parts = [p.strip() for p in cleaned.split("|")]
    if len(parts) < 3 or not parts[0]:
        return {}
    asns = [f"AS{tok.lstrip('ASas')}" for tok in parts[0].split() if tok.strip().isdigit()]
    if not asns:
        return {}
    return {
        "asns": _dedup_preserve(asns),
        "cidr": parts[1] if len(parts) > 1 else "",
        "country": parts[2].upper() if len(parts) > 2 else "",
        "rir": parts[3].lower() if len(parts) > 3 else "",
    }


def query_ip_asn_doh(ip_str: str) -> dict:
    """Resolve Team Cymru origin ASN hints via bounded HTTPS DoH JSON (no dig binary)."""
    try:
        ip_obj = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return {"ok": False, "error": "Invalid IP address"}
    if not _is_global_public_ip(ip_obj):
        return {"ok": False, "error": "Non-public IP excluded from ASN lookup"}
    rev = ip_obj.reverse_pointer
    if rev.endswith(".in-addr.arpa"):
        query_name = rev[:-len(".in-addr.arpa")] + ".origin.asn.cymru.com"
    elif rev.endswith(".ip6.arpa"):
        query_name = rev[:-len(".ip6.arpa")] + ".origin6.asn.cymru.com"
    else:
        return {"ok": False, "error": "Unsupported reverse pointer"}
    try:
        resp = fetch("https://dns.google/resolve?name=" + quote(query_name, safe="") + "&type=TXT", max_bytes=65536)
        if resp.status != 200:
            return {"ok": False, "error": f"DoH ASN lookup HTTP {resp.status}"}
        payload = json.loads(resp.body)
        if not isinstance(payload, dict):
            return {"ok": False, "error": "Invalid DoH JSON payload"}
        for answer in payload.get("Answer", []) or []:
            if isinstance(answer, dict) and answer.get("type") == 16:
                parsed = _parse_cymru_txt_record(str(answer.get("data", "")))
                if parsed:
                    return {"ok": True, "source": "CYMRU_DOH_TXT", "queried_name": query_name, **parsed}
        return {"ok": False, "error": "No Cymru ASN TXT record returned"}
    except (ValueError, OSError, KeyError, TypeError) as exc:
        return {"ok": False, "error": str(exc)}


def query_ip_rdap(ip_str: str, bootstrap_cache: dict[int, dict] | None = None) -> dict:
    """Query authoritative RIR IP RDAP via IANA bootstrap with Team Cymru DoH ASN fallback."""
    try:
        ip_obj = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return {"ok": False, "ip": str(ip_str), "error": "Invalid IP address", "trusted_as_instructions": False}
    if not _is_global_public_ip(ip_obj):
        return {"ok": False, "ip": str(ip_obj), "error": "Non-public IP excluded from IP RDAP", "trusted_as_instructions": False}
    norm_ip = str(ip_obj)
    errors: list[str] = []
    summary: dict = {}
    rdap_source = ""
    rdap_ok = False
    try:
        cache = bootstrap_cache if bootstrap_cache is not None else {}
        if ip_obj.version not in cache:
            b_url = "https://data.iana.org/rdap/ipv4.json" if ip_obj.version == 4 else "https://data.iana.org/rdap/ipv6.json"
            b_resp = fetch(b_url, max_bytes=2 * 1024 * 1024)
            if b_resp.status != 200:
                raise ValueError(f"IANA IPv{ip_obj.version} bootstrap HTTP {b_resp.status}")
            cache[ip_obj.version] = json.loads(b_resp.body)
        service = _find_ip_rdap_service(cache[ip_obj.version], ip_obj)
        resp = fetch(service.rstrip("/") + "/ip/" + quote(norm_ip, safe=""))
        if resp.status != 200:
            raise ValueError(f"IP RDAP HTTP {resp.status}")
        document = json.loads(resp.body)
        if not isinstance(document, dict) or document.get("errorCode"):
            raise ValueError("Invalid IP RDAP response document")
        summary = parse_rdap_ip_json(document, queried_ip=norm_ip)
        rdap_source = resp.url
        rdap_ok = bool(summary)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        errors.append(str(exc))

    asn_source = "RIR_RDAP" if summary.get("asns") else ""
    if not summary.get("asns"):
        cymru = query_ip_asn_doh(norm_ip)
        if cymru.get("ok"):
            asn_source = "CYMRU_DOH_TXT"
            if not summary:
                summary = {"ip": norm_ip, "handle": "", "network_name": "", "country": cymru.get("country", ""),
                           "holder": "", "cidrs": [cymru["cidr"]] if cymru.get("cidr") else [],
                           "asns": cymru["asns"], "abuse_emails": []}
            else:
                summary["asns"] = cymru["asns"]
                if not summary.get("cidrs") and cymru.get("cidr"):
                    summary["cidrs"] = [cymru["cidr"]]
                if not summary.get("country") and cymru.get("country"):
                    summary["country"] = cymru["country"]
        elif cymru.get("error"):
            errors.append(cymru["error"])
    return {
        "ok": bool(rdap_ok or summary.get("asns")),
        "rdap_ok": rdap_ok,
        "ip": norm_ip,
        "source": rdap_source or ("CYMRU_DOH_TXT" if summary.get("asns") else ""),
        "asn_source": asn_source,
        "summary": summary,
        "errors": errors,
        "use": "HOSTING_HINT_NOT_PROOF_OF_ATTRIBUTION",
        "trusted_as_instructions": False,
    }


def query_ip_intel(ips: list[str], limit: int = 2) -> list[dict]:
    """Query bounded RIR IP RDAP + ASN attribution leads for distinct global public IPs."""
    if limit < 1:
        return []
    unique_public: list[str] = []
    seen: set[str] = set()
    for raw in ips:
        try:
            ip_obj = ipaddress.ip_address(str(raw).strip())
        except ValueError:
            continue
        norm = str(ip_obj)
        if _is_global_public_ip(ip_obj) and norm not in seen:
            seen.add(norm)
            unique_public.append(norm)
    bootstrap_cache: dict[int, dict] = {}
    return [query_ip_rdap(ip, bootstrap_cache=bootstrap_cache) for ip in unique_public[:limit]]


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
    ip_candidates = [*( [report["peer_ip"]] if report.get("peer_ip") else [] ), *(dns.get("A") or []), *(dns.get("AAAA") or [])]
    report["ip_intel"] = query_ip_intel(ip_candidates, limit=2) if ip_candidates else []
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
