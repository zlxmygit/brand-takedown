from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from brand_registry import (
    is_allowlisted_url,
    load_brand_profile,
    normalize_hostname,
    sanitize_http_url,
)

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

SHOPIFY_DOMAIN_RE = re.compile(r"([a-z0-9][a-z0-9-]*\.myshopify\.com)", re.IGNORECASE)
SHOPIFY_SHOP_ID_RE = re.compile(r'(?:"shopId"|x-shopid)\s*[:=]\s*"?(\d{6,15})"?', re.IGNORECASE)
STRIPE_PK_RE = re.compile(r"\b(pk_live_[0-9a-zA-Z]{16,})\b")
PAYPAL_MERCHANT_RE = re.compile(r"merchant-id=([A-Z0-9]{8,24})", re.IGNORECASE)
PAYPAL_CLIENT_RE = re.compile(r"paypal\.com/sdk/js\?[^\"']*client-id=([A-Za-z0-9_-]{12,})", re.IGNORECASE)
GA4_ID_RE = re.compile(r"\b(G-[A-Z0-9]{6,14}|UA-\d{4,12}-\d{1,4})\b")
META_PIXEL_RE = re.compile(r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]\s*\)")
EMAIL_RE = re.compile(r"\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,12})\b")
SOCIAL_LINK_RE = re.compile(
    r"(https?://(?:www\.)?(?:wa\.me|api\.whatsapp\.com|facebook\.com|instagram\.com|tiktok\.com|youtube\.com|t\.me)/[^\s\"'<>]+)",
    re.IGNORECASE,
)

PROXY_ENV_KEYS = ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
EXCLUDED_MANIFEST_FILES = {"evidence-manifest.json", "recon-report.json"}


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp_path, path)


def _dedup_preserve(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        val = item.strip()
        if val and val not in seen:
            seen.add(val)
            out.append(val)
    return out


def _clean_direct_env() -> dict[str, str]:
    env = dict(os.environ)
    for k in PROXY_ENV_KEYS:
        env.pop(k, None)
    return env


def _run_cmd(cmd: list[str], timeout: int = 25, strip_proxy_env: bool = True) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=_clean_direct_env() if strip_proxy_env else None,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as exc:
        return 127, "", str(exc)


def _filter_valid_ips(lines: list[str]) -> list[str]:
    valid: list[str] = []
    for raw in lines:
        token = raw.strip().rstrip(".")
        if not token or token.startswith(";"):
            continue
        try:
            ip_obj = ipaddress.ip_address(token)
            valid.append(str(ip_obj))
        except ValueError:
            continue
    return _dedup_preserve(valid)


def extract_storefront_fingerprints(html: str, headers_text: str = "") -> dict:
    combined = (headers_text or "") + "\n" + (html or "")
    lower_html = (html or "").lower()
    lower_headers = (headers_text or "").lower()

    shopify_domains = [m.lower() for m in SHOPIFY_DOMAIN_RE.findall(combined)]
    shopify_ids = SHOPIFY_SHOP_ID_RE.findall(combined)

    platform = "custom_or_unknown"
    if shopify_domains or "cdn.shopify.com" in lower_html or "x-shopid:" in lower_headers:
        platform = "shopify"
    elif "shoplazza" in lower_html or "cdn.shoplazza.com" in lower_html:
        platform = "shoplazza"
    elif "myshopline.com" in lower_html or "shoplinecdn" in lower_html:
        platform = "shopline"
    elif "wp-content/plugins/woocommerce" in lower_html or "woocommerce" in lower_html:
        platform = "woocommerce"
    elif "bigcommerce" in lower_html:
        platform = "bigcommerce"
    elif "wixstatic.com" in lower_html:
        platform = "wix"

    stripe_keys = _dedup_preserve(STRIPE_PK_RE.findall(combined))
    paypal_ids = _dedup_preserve(PAYPAL_MERCHANT_RE.findall(combined) + PAYPAL_CLIENT_RE.findall(combined))
    ga_ids = _dedup_preserve(GA4_ID_RE.findall(combined))
    pixel_ids = _dedup_preserve(META_PIXEL_RE.findall(combined))

    raw_emails = [e.lower() for e in EMAIL_RE.findall(html or "")]
    ignored_suffixes = (".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif", ".js", ".css", "sentry.io", "example.com")
    emails = _dedup_preserve([e for e in raw_emails if not e.endswith(ignored_suffixes)])
    social_links = _dedup_preserve(SOCIAL_LINK_RE.findall(html or ""))

    cdn_hint = ""
    if "server: cloudflare" in lower_headers or "cf-ray:" in lower_headers:
        cdn_hint = "cloudflare"
    elif "fastly" in lower_headers:
        cdn_hint = "fastly"
    elif "akamai" in lower_headers:
        cdn_hint = "akamai"

    return {
        "platform": platform,
        "cdn_hint": cdn_hint,
        "shopify_domain": shopify_domains[0] if shopify_domains else "",
        "shopify_shop_id": shopify_ids[0] if shopify_ids else "",
        "stripe_publishable_keys": stripe_keys,
        "paypal_identifiers": paypal_ids,
        "ga_ids": ga_ids,
        "meta_pixel_ids": pixel_ids,
        "contact_emails": emails,
        "social_links": social_links,
        "needs_checkout_probe": len(stripe_keys) == 0 and len(paypal_ids) == 0,
    }


def parse_whois_summary(raw_whois: str) -> dict:
    registrar = ""
    iana_id = ""
    creation_date = ""
    abuse_emails: list[str] = []
    name_servers: list[str] = []
    status_codes: list[str] = []

    for raw_line in (raw_whois or "").splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        k_low = key.strip().lower()
        v_clean = val.strip()
        if not v_clean:
            continue

        if k_low in ("registrar", "sponsoring registrar") and not registrar:
            registrar = v_clean
        elif k_low == "registrar iana id" and not iana_id:
            iana_id = v_clean
        elif k_low in ("creation date", "registered on", "registration time") and not creation_date:
            creation_date = v_clean
        elif "abuse" in k_low and "email" in k_low:
            for em in EMAIL_RE.findall(v_clean):
                abuse_emails.append(em.lower())
        elif k_low in ("name server", "nserver"):
            ns_token = v_clean.split()[0].lower().rstrip(".")
            name_servers.append(ns_token)
        elif k_low in ("domain status", "status"):
            status_token = v_clean.split()[0].lower()
            status_codes.append(status_token)

    return {
        "registrar": registrar,
        "registrar_iana_id": iana_id,
        "creation_date": creation_date,
        "abuse_emails": _dedup_preserve(abuse_emails),
        "name_servers": _dedup_preserve(name_servers),
        "status_codes": _dedup_preserve(status_codes),
    }


def _build_dig_cmd(clean_host: str, rtype: str) -> list[str]:
    return ["/usr/bin/dig", "+short", clean_host, rtype]


def query_direct_dns(host: str) -> dict:
    clean_host = normalize_hostname(host)
    if not clean_host:
        raise ValueError(f"Invalid hostname for DNS query: {host!r}")

    records: dict = {"dns_query_ok": False}
    for rtype in ("A", "AAAA", "CNAME", "NS", "MX", "TXT"):
        rc, out, _ = _run_cmd(_build_dig_cmd(clean_host, rtype), timeout=12, strip_proxy_env=True)
        if rtype == "A" and rc == 0:
            records["dns_query_ok"] = True
        raw_lines = [ln.strip() for ln in out.splitlines() if ln.strip() and not ln.strip().startswith(";")]
        if rtype in ("A", "AAAA"):
            records[rtype] = _filter_valid_ips(raw_lines)
        else:
            records[rtype] = _dedup_preserve([ln.rstrip(".") for ln in raw_lines])
    return records


def _parse_der_cert_with_openssl(der_bytes: bytes) -> dict[str, str]:
    parsed_meta: dict[str, str] = {}
    try:
        proc = subprocess.run(
            [
                "/usr/bin/openssl",
                "x509",
                "-inform",
                "DER",
                "-noout",
                "-subject",
                "-issuer",
                "-dates",
                "-serial",
                "-text",
            ],
            input=der_bytes,
            capture_output=True,
            timeout=10,
            check=False,
        )
        x509_text = proc.stdout.decode("utf-8", errors="replace")
        for line in x509_text.splitlines():
            s = line.strip()
            if s.startswith("subject="):
                parsed_meta["subject"] = s.partition("=")[2].strip()
            elif s.startswith("issuer="):
                parsed_meta["issuer"] = s.partition("=")[2].strip()
            elif s.startswith("notBefore="):
                parsed_meta["not_before"] = s.partition("=")[2].strip()
            elif s.startswith("notAfter="):
                parsed_meta["not_after"] = s.partition("=")[2].strip()
            elif s.startswith("serial="):
                parsed_meta["serial"] = s.partition("=")[2].strip()
            elif "DNS:" in s and "subject_alt_names" not in parsed_meta:
                parsed_meta["subject_alt_names"] = s
    except (subprocess.TimeoutExpired, OSError):
        pass
    return parsed_meta


def capture_direct_tls_info(host: str, port: int = 443) -> dict:
    clean_host = normalize_hostname(host)
    if not clean_host:
        return {"reachable": False, "error": "invalid_hostname"}

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((clean_host, port), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=clean_host) as tls_sock:
                der_bytes = tls_sock.getpeercert(binary_form=True)
                cipher = tls_sock.cipher()
    except OSError as exc:
        return {"reachable": False, "error": str(exc)}

    if not der_bytes:
        return {"reachable": False, "error": "no_peer_certificate"}

    sha256_fp = hashlib.sha256(der_bytes).hexdigest()
    parsed_meta = _parse_der_cert_with_openssl(der_bytes)

    return {
        "reachable": True,
        "sha256_fingerprint": sha256_fp,
        "cipher": cipher[0] if cipher else "",
        **parsed_meta,
    }


def build_evidence_manifest(
    evidence_dir: Path,
    target_url: str,
    direct_dns_ips: list[str],
    proxy_used: bool,
) -> dict:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    files_list: list[dict] = []
    for item in sorted(evidence_dir.iterdir()):
        if not item.is_file() or item.name in EXCLUDED_MANIFEST_FILES or item.name.endswith(".tmp"):
            continue
        raw_bytes = item.read_bytes()
        sha = hashlib.sha256(raw_bytes).hexdigest()
        files_list.append(
            {
                "filename": item.name,
                "size_bytes": len(raw_bytes),
                "sha256": sha,
            }
        )

    manifest = {
        "target_url": target_url,
        "captured_at_utc": _utc_now_iso(),
        "direct_dns_ips": _dedup_preserve(direct_dns_ips),
        "http_fetch_used_proxy": bool(proxy_used),
        "files": files_list,
    }
    _atomic_write_json(evidence_dir / "evidence-manifest.json", manifest)
    return manifest


def refresh_case_manifest(case_dir: Path) -> dict:
    ev_dir = case_dir.expanduser().resolve() / "evidence"
    existing = ev_dir / "evidence-manifest.json"
    if existing.is_file():
        prev = json.loads(existing.read_text(encoding="utf-8"))
        target_url = prev.get("target_url", "")
        direct_ips = prev.get("direct_dns_ips", [])
        proxy_used = prev.get("http_fetch_used_proxy", False)
    else:
        target_url, direct_ips, proxy_used = "", [], False

    updated = build_evidence_manifest(ev_dir, target_url, direct_ips, proxy_used)
    report_path = ev_dir / "recon-report.json"
    if report_path.is_file():
        try:
            rep = json.loads(report_path.read_text(encoding="utf-8"))
            rep["evidence_manifest"] = updated
            _atomic_write_json(report_path, rep)
        except json.JSONDecodeError:
            pass
    return updated


def _build_curl_cmd(
    url: str,
    head_only: bool,
    proxy: str | None = None,
    referer: str | None = None,
) -> list[str]:
    clean_url = sanitize_http_url(url)
    cmd = [
        "/usr/bin/curl",
        "-sS",
        "-L",
        "--proto",
        "=http,https",
        "--globoff",
        "--max-time",
        "20" if head_only else "25",
        "-A",
        BROWSER_UA,
        "-H",
        "Accept-Language: en-US,en;q=0.9",
    ]
    if head_only:
        cmd.extend(["-I", "--suppress-connect-headers"])
    if proxy:
        cmd.extend(["--proxy", proxy])
    else:
        cmd.extend(["--noproxy", "*"])
    if referer:
        cmd.extend(["-e", referer])
    cmd.extend(["--", clean_url])
    return cmd


def _curl_fetch(url: str, proxy: str | None = None, referer: str | None = None) -> tuple[str, str]:
    headers_cmd = _build_curl_cmd(url, head_only=True, proxy=proxy, referer=referer)
    body_cmd = _build_curl_cmd(url, head_only=False, proxy=proxy, referer=referer)
    _, headers_out, _ = _run_cmd(headers_cmd, timeout=25, strip_proxy_env=True)
    _, body_out, _ = _run_cmd(body_cmd, timeout=30, strip_proxy_env=True)
    return headers_out, body_out


def run_recon(
    target_url: str,
    case_dir: Path,
    allowlist_domains: list[str],
    proxy: str | None = None,
    referer: str | None = None,
) -> dict:
    if is_allowlisted_url(target_url, allowlist_domains):
        raise ValueError(
            f"SAFETY ABORT: {target_url!r} matches brand allowlist {allowlist_domains!r}. Recon aborted."
        )
    clean_url = sanitize_http_url(target_url)
    host = normalize_hostname(clean_url)
    if not host:
        raise ValueError(f"Invalid target URL: {target_url!r}")

    ev_dir = case_dir.expanduser().resolve() / "evidence"
    ev_dir.mkdir(parents=True, exist_ok=True)

    # 1. Direct unproxied DNS, WHOIS & TLS so proxy nodes never contaminate forensic network records
    dns_records = query_direct_dns(host)
    _, raw_whois, _ = _run_cmd(["/usr/bin/whois", "--", host], timeout=20, strip_proxy_env=True)
    whois_summary = parse_whois_summary(raw_whois)
    tls_info = capture_direct_tls_info(host)

    (ev_dir / "whois.txt").write_text(raw_whois or "", encoding="utf-8")
    _atomic_write_json(ev_dir / "dns.json", dns_records)
    _atomic_write_json(ev_dir / "tls.json", tls_info)

    # 2. HTTP fetch (optionally routed via explicit proxy; otherwise --noproxy '*' enforced)
    headers_text, html_body = _curl_fetch(clean_url, proxy=proxy, referer=referer)
    (ev_dir / "headers.txt").write_text(headers_text or "", encoding="utf-8")
    (ev_dir / "raw.html").write_text(html_body or "", encoding="utf-8")

    _, meta_body = _curl_fetch(f"https://{host}/meta.json", proxy=proxy, referer=referer)
    if meta_body and meta_body.strip().startswith("{"):
        (ev_dir / "shopify_meta.json").write_text(meta_body, encoding="utf-8")
        html_for_fp = html_body + "\n" + meta_body
    else:
        html_for_fp = html_body

    fingerprints = extract_storefront_fingerprints(html_for_fp, headers_text)
    direct_ips = dns_records.get("A", []) + dns_records.get("AAAA", [])
    manifest = build_evidence_manifest(
        evidence_dir=ev_dir,
        target_url=clean_url,
        direct_dns_ips=direct_ips,
        proxy_used=bool(proxy),
    )

    recon_report = {
        "target_url": clean_url,
        "hostname": host,
        "captured_at_utc": manifest["captured_at_utc"],
        "dns": dns_records,
        "whois": whois_summary,
        "tls": tls_info,
        "fingerprints": fingerprints,
        "evidence_manifest": manifest,
    }
    _atomic_write_json(ev_dir / "recon-report.json", recon_report)

    case_file = case_dir / "case.json"
    if case_file.is_file():
        case_data = json.loads(case_file.read_text(encoding="utf-8"))
        case_data["infrastructure_baseline"] = {
            "ips": direct_ips,
            "nameservers": dns_records.get("NS", []) or whois_summary.get("name_servers", []),
            "registrar": whois_summary.get("registrar", ""),
            "registrar_iana_id": whois_summary.get("registrar_iana_id", ""),
            "registrar_abuse_emails": whois_summary.get("abuse_emails", []),
            "saas_platform": fingerprints.get("platform", ""),
            "saas_shop_id": fingerprints.get("shopify_domain") or fingerprints.get("shopify_shop_id", ""),
        }
        if case_data.get("status") == "DISCOVERED":
            case_data["status"] = "EVIDENCE_LOCKED"
        case_data["updated_at"] = _utc_now_iso()
        _atomic_write_json(case_file, case_data)

    return recon_report


def trigger_wayback_save(target_url: str, allowlist_domains: list[str] | None = None) -> dict:
    if allowlist_domains and is_allowlisted_url(target_url, allowlist_domains):
        raise ValueError(
            f"SAFETY ABORT: {target_url!r} matches brand allowlist {allowlist_domains!r}. Wayback save aborted."
        )
    clean_url = sanitize_http_url(target_url)
    save_endpoint = f"https://web.archive.org/save/{clean_url}"
    cmd = _build_curl_cmd(save_endpoint, head_only=True, proxy=None, referer=None)
    code, headers_out, err = _run_cmd(cmd, timeout=35, strip_proxy_env=True)
    content_loc = ""
    for line in headers_out.splitlines():
        if line.lower().startswith("content-location:") or line.lower().startswith("location:"):
            content_loc = line.partition(":")[2].strip()
            break
    archive_url = f"https://web.archive.org{content_loc}" if content_loc.startswith("/") else content_loc
    return {
        "target_url": clean_url,
        "exit_code": code,
        "archive_url": archive_url or f"https://web.archive.org/web/*/{clean_url}",
        "error": err.strip(),
    }


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Forensic reconnaissance & Wayback archival helper.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="Run silent recon and lock SHA-256 evidence manifest")
    p_run.add_argument("--slug", required=True, help="Registered brand slug")
    p_run.add_argument("--url", required=True, help="Infringing URL")
    p_run.add_argument("--case-dir", type=Path, required=True, help="Case directory path")
    p_run.add_argument("--proxy", default=None, help="Optional HTTP/SOCKS5 proxy for page fetch")
    p_run.add_argument("--referer", default=None, help="Optional simulated ad referer URL")

    p_wb = sub.add_parser("archive-wayback", help="Trigger Wayback Machine snapshot AFTER local evidence & Tier-1 prep")
    p_wb.add_argument("--slug", default=None, help="Optional brand slug to enforce allowlist guard")
    p_wb.add_argument("--url", required=True)

    p_rehash = sub.add_parser("refresh-manifest", help="Recompute SHA-256 manifest after adding browser screenshots")
    p_rehash.add_argument("--case-dir", type=Path, required=True)

    args = parser.parse_args(argv)

    if args.cmd == "run":
        _, prof = load_brand_profile(args.slug)
        report = run_recon(
            target_url=args.url,
            case_dir=args.case_dir,
            allowlist_domains=prof.get("allowlist_domains", []),
            proxy=args.proxy,
            referer=args.referer,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "archive-wayback":
        allow = None
        if args.slug:
            _, prof = load_brand_profile(args.slug)
            allow = prof.get("allowlist_domains", [])
        res = trigger_wayback_save(args.url, allowlist_domains=allow)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "refresh-manifest":
        updated = refresh_case_manifest(args.case_dir)
        print(json.dumps(updated, ensure_ascii=False, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(_main())
