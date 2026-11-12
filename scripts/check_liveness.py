from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from brand_registry import load_brand_profile, normalize_hostname, sanitize_http_url
from recon_target import BROWSER_UA, _clean_direct_env, parse_whois_summary, query_direct_dns

PLATFORM_TAKEDOWN_BANNERS = (
    "sorry, this shop is currently unavailable",
    "this store is unavailable",
    "this shop is unavailable",
    "this account has been suspended",
    "website has been suspended",
    "store has been closed",
)

SCRIPT_STYLE_COMMENT_RE = re.compile(
    r"(<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>|<!--.*?-->)",
    re.IGNORECASE | re.DOTALL,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp_path, path)


def _visible_html_text(html: str) -> str:
    stripped = SCRIPT_STYLE_COMMENT_RE.sub(" ", html or "")
    return stripped.lower()


def classify_liveness(
    http_status: int,
    html: str,
    dns_ips: list[str],
    whois_statuses: list[str],
    brand_keywords: list[str],
    baseline_ips: list[str],
    dns_query_ok: bool = True,
) -> dict:
    lower_statuses = [s.lower() for s in (whois_statuses or [])]
    hold_flags = [s for s in lower_statuses if "clienthold" in s or "serverhold" in s or "redemptionperiod" in s]
    if hold_flags:
        return {
            "verdict": "CONFIRMED_DOWN_DNS",
            "reason": f"Registry/Registrar EPP suspension confirmed: {hold_flags}",
        }
    if len(dns_ips) == 0:
        if dns_query_ok:
            return {
                "verdict": "CONFIRMED_DOWN_DNS",
                "reason": "Authoritative DNS query succeeded with zero A/AAAA records (NXDOMAIN / unrouted).",
            }
        return {
            "verdict": "HTTP_ERROR_NEEDS_CROSSCHECK",
            "reason": "Local DNS resolver failed/timed out; refusing to close case without verified resolution.",
        }

    visible_lower = _visible_html_text(html)
    clean_keywords = [k.strip().lower() for k in (brand_keywords or []) if k.strip()]
    matched_kw = [k for k in clean_keywords if k in visible_lower]

    matched_banner = next((b for b in PLATFORM_TAKEDOWN_BANNERS if b in visible_lower), "")
    if matched_banner and (http_status in (402, 403, 404, 410, 423, 451, 503) or not matched_kw):
        return {
            "verdict": "CONFIRMED_DOWN_PLATFORM",
            "reason": f"Storefront suspension banner matched ({matched_banner!r}) with HTTP {http_status}.",
        }

    if http_status >= 400 or http_status == 0:
        return {
            "verdict": "HTTP_ERROR_NEEDS_CROSSCHECK",
            "reason": (
                f"HTTP status={http_status} while DNS still resolves to {dns_ips}; "
                "requires browser/proxy cross-check to rule out Geo-IP or User-Agent cloaking before closing."
            ),
        }

    if clean_keywords and not matched_kw:
        return {
            "verdict": "SUSPECTED_CLOAKING",
            "reason": (
                f"HTTP {http_status} returned visible content without any brand keywords {clean_keywords}; "
                "likely switched to a decoy Safe Page (Cloaking)."
            ),
        }

    base_set = {ip.strip() for ip in (baseline_ips or []) if ip.strip()}
    curr_set = {ip.strip() for ip in (dns_ips or []) if ip.strip()}
    if base_set and curr_set and base_set.isdisjoint(curr_set):
        return {
            "verdict": "ACTIVE_ESCAPED_INFRA",
            "reason": f"Site still active with keywords {matched_kw}, but DNS IPs migrated from {sorted(base_set)} to {sorted(curr_set)}.",
        }

    return {
        "verdict": "STILL_ACTIVE",
        "reason": f"Infringing content remains live (HTTP {http_status}, matched={matched_kw}, ips={sorted(curr_set)}).",
    }


def _curl_probe(url: str, proxy: str | None = None, referer: str | None = None) -> tuple[int, str]:
    clean_url = sanitize_http_url(url)
    cmd = [
        "/usr/bin/curl",
        "-sS",
        "-L",
        "--proto",
        "=http,https",
        "--globoff",
        "--max-time",
        "25",
        "-A",
        BROWSER_UA,
        "-H",
        "Accept-Language: en-US,en;q=0.9",
        "-w",
        "\n__HTTP_STATUS__:%{http_code}",
    ]
    if proxy:
        cmd.extend(["--proxy", proxy])
    else:
        cmd.extend(["--noproxy", "*"])
    if referer:
        cmd.extend(["-e", referer])
    cmd.extend(["--", clean_url])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False, env=_clean_direct_env())
        out = proc.stdout or ""
    except (subprocess.TimeoutExpired, OSError):
        return 0, ""

    if "\n__HTTP_STATUS__:" in out:
        body, _, code_str = out.rpartition("\n__HTTP_STATUS__:")
        try:
            return int(code_str.strip()), body
        except ValueError:
            return 0, body
    return 0, out


def probe_case(
    case_dir: Path,
    brand_keywords: list[str],
    proxy: str | None = None,
    referer: str | None = None,
) -> dict:
    case_file = case_dir.expanduser().resolve() / "case.json"
    case_data = json.loads(case_file.read_text(encoding="utf-8"))
    target_urls = case_data.get("target_urls") or [f"https://{case_data['primary_domain']}/"]
    primary_url = sanitize_http_url(target_urls[0])
    host = normalize_hostname(primary_url)

    dns_records = query_direct_dns(host)
    direct_ips = dns_records.get("A", []) + dns_records.get("AAAA", [])
    dns_ok = bool(dns_records.get("dns_query_ok", False))

    try:
        whois_proc = subprocess.run(
            ["/usr/bin/whois", "--", host],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env=_clean_direct_env(),
        )
        whois_info = parse_whois_summary(whois_proc.stdout or "")
    except (subprocess.TimeoutExpired, OSError):
        whois_info = {"status_codes": []}

    http_code, html_body = _curl_probe(primary_url, proxy=proxy, referer=referer)
    baseline_ips = case_data.get("infrastructure_baseline", {}).get("ips", [])

    classification = classify_liveness(
        http_status=http_code,
        html=html_body,
        dns_ips=direct_ips,
        whois_statuses=whois_info.get("status_codes", []),
        brand_keywords=brand_keywords,
        baseline_ips=baseline_ips,
        dns_query_ok=dns_ok,
    )

    prev_status = case_data.get("status", "ACTIVE_ENFORCEMENT")
    verdict = classification["verdict"]
    resurrected = False

    if verdict in ("CONFIRMED_DOWN_DNS", "CONFIRMED_DOWN_PLATFORM"):
        case_data["status"] = "WATCHLIST_RESURRECTION"
    elif prev_status in ("TAKEN_DOWN", "WATCHLIST_RESURRECTION") and verdict in ("STILL_ACTIVE", "ACTIVE_ESCAPED_INFRA"):
        case_data["status"] = "ACTIVE_ENFORCEMENT"
        resurrected = True

    probe_record = {
        "checked_at_utc": _utc_now_iso(),
        "case_id": case_data["case_id"],
        "primary_domain": host,
        "target_url": primary_url,
        "http_status": http_code,
        "direct_dns_ips": direct_ips,
        "dns_query_ok": dns_ok,
        "whois_statuses": whois_info.get("status_codes", []),
        "verdict": verdict,
        "reason": classification["reason"],
        "resurrected_alert": resurrected,
        "case_status_after_probe": case_data["status"],
    }

    case_data["last_liveness_probe"] = probe_record
    case_data["updated_at"] = probe_record["checked_at_utc"]
    _atomic_write_json(case_file, case_data)
    return probe_record


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Anti-cloaking liveness & infrastructure escape probe.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_one = sub.add_parser("probe", help="Probe a single case directory")
    p_one.add_argument("--slug", required=True)
    p_one.add_argument("--case-dir", type=Path, required=True)
    p_one.add_argument("--proxy", default=None)
    p_one.add_argument("--referer", default=None)

    p_all = sub.add_parser("patrol", help="Probe all cases for a brand (including resurrection watchlist)")
    p_all.add_argument("--slug", required=True)
    p_all.add_argument("--proxy", default=None)
    p_all.add_argument("--referer", default=None)

    args = parser.parse_args(argv)
    brand_dir, profile = load_brand_profile(args.slug)
    keywords = profile.get("keyword_watch_patterns") or [profile.get("brand_name", ""), profile.get("brand_slug", "")]

    if args.cmd == "probe":
        res = probe_case(args.case_dir, keywords, proxy=args.proxy, referer=args.referer)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "patrol":
        cases_root = brand_dir / "cases"
        results = []
        if cases_root.is_dir():
            for child in sorted(cases_root.iterdir()):
                if (child / "case.json").is_file():
                    results.append(probe_case(child, keywords, proxy=args.proxy, referer=args.referer))
        print(json.dumps({"probed_count": len(results), "results": results}, ensure_ascii=False, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(_main())
