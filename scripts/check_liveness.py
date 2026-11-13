"""Observe every case target without making automatic legal or takedown findings."""
from __future__ import annotations

import argparse
from html_tools import VisibleText, visible_html_text
import json
from pathlib import Path
import sys

from brand_registry import DEFAULT_REGISTRY_PATH, check_target, load_brand_profile, normalize_hostname, profile_allowlist, utc_now
from case_manager import assert_case_brand, case_profile, load_case, mutate_case
from recon_target import query_direct_dns, query_rdap
from safe_http import fetch

PLATFORM_TAKEDOWN_BANNERS = ("sorry, this shop is currently unavailable", "this store is unavailable", "this account has been suspended", "website has been suspended", "store has been closed")


_VisibleText = VisibleText
_visible_html_text = visible_html_text


def classify_liveness(http_status: int, html: str, dns_ips: list[str], whois_statuses: list[str],
                      brand_keywords: list[str], baseline_ips: list[str], dns_query_ok=True) -> dict:
    # No HTTP, DNS, EPP or page banner alone closes a case. Contradictory signals are unknown.
    if not dns_query_ok or not dns_ips:
        return {"verdict": "UNKNOWN_REQUIRES_REVIEW", "reason": "DNS result missing or incomplete; HTTP does not establish authoritative DNS suspension"}
    text = _visible_html_text(html)
    matches = [k for k in brand_keywords if isinstance(k, str) and k.strip() and k.lower() in text]
    banner = any(b in text for b in PLATFORM_TAKEDOWN_BANNERS)
    normalized_statuses = {str(s).strip().lower().replace(" ", "") for s in whois_statuses if str(s).strip()}
    if normalized_statuses & {"clienthold", "serverhold", "redemptionperiod"}:
        return {"verdict": "DOWN_CANDIDATE_REVIEW", "reason": "Registration status is a lead requiring independent review"}
    if banner or http_status >= 400:
        return {"verdict": "DOWN_CANDIDATE_REVIEW", "reason": "Page/status signal is not independent proof of a platform takedown"}
    if not 200 <= http_status < 300:
        return {"verdict": "UNKNOWN_REQUIRES_REVIEW", "reason": "Transport or unexpected HTTP result"}
    changed = bool(baseline_ips and set(dns_ips).isdisjoint(baseline_ips))
    return {"verdict": "CONTENT_PRESENT" if matches else "CONTENT_CHANGED_REVIEW", "matched_keywords": matches,
            "infrastructure_changed_hint": changed, "reason": "Observed page content only; not an infringement or operator-attribution conclusion"}


def probe_case(case_dir: Path, brand_keywords: list[str], proxy=None, referer=None, *, check_rdap: bool = False) -> dict:
    data = load_case(case_dir)
    profile = case_profile(case_dir)
    if proxy or referer:
        raise ValueError("Proxy/referer paths disabled")
    urls = list(data["target_urls"])
    urls.extend("https://" + lead["domain"] + "/" for lead in data["linked_payment_cloak_domains"])
    results = []
    dns_cache: dict[str, dict] = {}
    rdap_cache: dict[str, dict] = {}
    for url in dict.fromkeys(urls):
        rdap_meta: dict = {}
        rdap_statuses: list[str] = []
        try:
            clean = check_target(url, profile)
            host = normalize_hostname(clean)
            if host not in dns_cache:
                dns_cache[host] = query_direct_dns(host)
            dns = dns_cache[host]
            if check_rdap:
                if host not in rdap_cache:
                    try:
                        rdap_cache[host] = query_rdap(host)
                    except (ValueError, OSError) as rdap_exc:
                        rdap_cache[host] = {"ok": False, "error": str(rdap_exc)}
                rdap_info = rdap_cache[host]
                if rdap_info.get("ok"):
                    rdap_statuses = list(rdap_info.get("summary", {}).get("status_codes", []))
                    rdap_meta["rdap_statuses"] = rdap_statuses
                    if rdap_info.get("queried_domain"):
                        rdap_meta["rdap_queried_domain"] = rdap_info["queried_domain"]
                else:
                    rdap_meta["rdap_statuses"] = []
                    if rdap_info.get("error"):
                        rdap_meta["rdap_error"] = rdap_info["error"]
            response = fetch(clean, profile_allowlist(profile))
            ips = dns.get("A", []) + dns.get("AAAA", [])
            observation = classify_liveness(response.status, response.body.decode("utf-8", errors="replace"), ips,
                rdap_statuses, brand_keywords, data["infrastructure_baseline"].get("ips", []), dns.get("dns_query_ok", False))
            results.append({"target_url": url, "final_url": response.url, "http_status": response.status,
                            "checked_at_utc": utc_now(), **rdap_meta, **observation})
        except (ValueError, OSError, TypeError, AttributeError, RecursionError) as exc:
            results.append({"target_url": url, "checked_at_utc": utc_now(), "verdict": "UNKNOWN_REQUIRES_REVIEW",
                            **rdap_meta, "error": str(exc)})
    active = any(r["verdict"] in ("CONTENT_PRESENT", "CONTENT_CHANGED_REVIEW") for r in results)
    record = {"checked_at_utc": utc_now(), "case_id": data["case_id"], "targets": results,
              "verdict": "CONTENT_OBSERVED" if active else "REVIEW_REQUIRED", "resurrected_alert": False}
    def update(current):
        review = current.get("liveness_review", {})
        down = review.get("decision") == "DOWN"
        scope_matches = (review.get("target_urls") == current["target_urls"] and
                         review.get("linked_domains") == [x["domain"] for x in current["linked_payment_cloak_domains"]])
        # A probe that started before a newer review cannot contradict that review.
        current_review_id = review.get("review_id")
        same_review = current_review_id == data.get("liveness_review", {}).get("review_id")
        legacy_down = not review and current.get("liveness_state") == "REVIEWED_DOWN"
        if active and same_review and (down or legacy_down):
            alert = current.setdefault("resurrection_alert", {
                "review_id": current_review_id, "first_observed_at": record["checked_at_utc"]})
            alert.update(last_observed_at=record["checked_at_utc"], targets=[r["target_url"] for r in results
                         if r["verdict"] in ("CONTENT_PRESENT", "CONTENT_CHANGED_REVIEW")])
        record["resurrected_alert"] = bool(current.get("resurrection_alert"))
        current["last_liveness_probe"] = record
        if down:
            current["liveness_state"] = ("CONTENT_RETURNED_REVIEW" if record["resurrected_alert"] else
                                         "REVIEWED_DOWN" if scope_matches else "SCOPE_CHANGED_REVIEW")
        elif same_review:
            current["liveness_state"] = record["verdict"]
        # Case and legal status are independent from network observations.
    after = mutate_case(case_dir, "liveness_observed", update)
    return {**record, "case_status_after_probe": after["status"], "liveness_state": after["liveness_state"]}


def patrol(brand_dir: Path, keywords: list[str], *, check_rdap: bool = False) -> dict:
    results, errors = [], []
    for child in sorted((brand_dir / "cases").iterdir()):
        if not child.is_dir():
            continue
        try:
            results.append(probe_case(child, keywords, check_rdap=check_rdap))
        except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError) as exc:
            errors.append({"case_dir": str(child), "error": str(exc)})
    failed_targets = sum(bool(t.get("error")) for result in results for t in result["targets"])
    return {"results": results, "errors": errors, "probed_count": len(results), "failed_target_count": failed_targets}


def _main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("probe", "patrol"):
        p = sub.add_parser(name); p.add_argument("--slug", required=True)
        p.add_argument("--check-rdap", action="store_true", help="Also query bounded IANA RDAP registration status hints")
        if name == "probe":
            p.add_argument("--case-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    directory, profile = load_brand_profile(args.slug, args.registry)
    keywords = profile.get("keyword_watch_patterns") or [profile["brand_name"]]
    if args.cmd == "probe":
        assert_case_brand(args.case_dir, directory)
        result = probe_case(args.case_dir, keywords, check_rdap=args.check_rdap)
    else:
        result = patrol(directory, keywords, check_rdap=args.check_rdap)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(bool(result.get("errors")) or bool(result.get("failed_target_count")) or any(t.get("error") for t in result.get("targets", [])))


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (ValueError, OSError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr); sys.exit(2)
