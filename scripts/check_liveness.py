"""Observe every case target without making automatic legal or takedown findings."""
from __future__ import annotations

import argparse
from html.parser import HTMLParser
import json
from pathlib import Path
import sys

from brand_registry import DEFAULT_REGISTRY_PATH, check_target, load_brand_profile, profile_allowlist, utc_now
from case_manager import assert_case_brand, case_profile, load_case, mutate_case
from recon_target import query_direct_dns
from safe_http import fetch

PLATFORM_TAKEDOWN_BANNERS = ("sorry, this shop is currently unavailable", "this store is unavailable", "this account has been suspended", "website has been suspended", "store has been closed")


class _VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(); self.stack = []; self.parts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        style = attrs.get("style", "").replace(" ", "").lower()
        hidden = (tag in ("script", "style", "template", "noscript") or "hidden" in attrs
                  or attrs.get("aria-hidden") == "true" or "display:none" in style or "visibility:hidden" in style)
        if tag not in ("area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"):
            self.stack.append((tag, hidden or any(h for _, h in self.stack)))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]; break

    def handle_data(self, data):
        if not any(hidden for _, hidden in self.stack):
            self.parts.append(data)


def _visible_html_text(html: str) -> str:
    parser = _VisibleText(); parser.feed(html)
    return " ".join(parser.parts).lower()


def classify_liveness(http_status: int, html: str, dns_ips: list[str], whois_statuses: list[str],
                      brand_keywords: list[str], baseline_ips: list[str], dns_query_ok=True) -> dict:
    # No HTTP, DNS, EPP or page banner alone closes a case. Contradictory signals are unknown.
    if not dns_query_ok or not dns_ips:
        return {"verdict": "UNKNOWN_REQUIRES_REVIEW", "reason": "DNS result missing or incomplete; HTTP does not establish authoritative DNS suspension"}
    text = _visible_html_text(html)
    matches = [k for k in brand_keywords if isinstance(k, str) and k.strip() and k.lower() in text]
    banner = any(b in text for b in PLATFORM_TAKEDOWN_BANNERS)
    if any(s.lower() in ("clienthold", "serverhold", "redemptionperiod") for s in whois_statuses):
        return {"verdict": "DOWN_CANDIDATE_REVIEW", "reason": "Registration status is a lead requiring independent review"}
    if banner or http_status >= 400:
        return {"verdict": "DOWN_CANDIDATE_REVIEW", "reason": "Page/status signal is not independent proof of a platform takedown"}
    if not 200 <= http_status < 300:
        return {"verdict": "UNKNOWN_REQUIRES_REVIEW", "reason": "Transport or unexpected HTTP result"}
    changed = bool(baseline_ips and set(dns_ips).isdisjoint(baseline_ips))
    return {"verdict": "CONTENT_PRESENT" if matches else "CONTENT_CHANGED_REVIEW", "matched_keywords": matches,
            "infrastructure_changed_hint": changed, "reason": "Observed page content only; not an infringement or operator-attribution conclusion"}


def probe_case(case_dir: Path, brand_keywords: list[str], proxy=None, referer=None) -> dict:
    data = load_case(case_dir)
    profile = case_profile(case_dir)
    if proxy or referer:
        raise ValueError("Proxy/referer paths disabled")
    urls = list(data["target_urls"])
    urls.extend("https://" + lead["domain"] + "/" for lead in data["linked_payment_cloak_domains"])
    results = []
    dns_cache = {}
    for url in dict.fromkeys(urls):
        try:
            clean = check_target(url, profile)
            from brand_registry import normalize_hostname
            host = normalize_hostname(clean)
            if host not in dns_cache:
                dns_cache[host] = query_direct_dns(host)
            dns = dns_cache[host]
            response = fetch(clean, profile_allowlist(profile))
            ips = dns.get("A", []) + dns.get("AAAA", [])
            observation = classify_liveness(response.status, response.body.decode("utf-8", errors="replace"), ips,
                [], brand_keywords, data["infrastructure_baseline"].get("ips", []), dns.get("dns_query_ok", False))
            results.append({"target_url": url, "final_url": response.url, "http_status": response.status,
                            "checked_at_utc": utc_now(), **observation})
        except (ValueError, OSError) as exc:
            results.append({"target_url": url, "checked_at_utc": utc_now(), "verdict": "UNKNOWN_REQUIRES_REVIEW", "error": str(exc)})
    active = any(r["verdict"] in ("CONTENT_PRESENT", "CONTENT_CHANGED_REVIEW") for r in results)
    record = {"checked_at_utc": utc_now(), "case_id": data["case_id"], "targets": results,
              "verdict": "CONTENT_OBSERVED" if active else "REVIEW_REQUIRED",
              "resurrected_alert": active and (data.get("liveness_state") == "REVIEWED_DOWN" or data["status"] in ("TAKEN_DOWN", "WATCHLIST_RESURRECTION"))}
    def update(current):
        current["last_liveness_probe"] = record
        current["liveness_state"] = record["verdict"]
        # Enforcement and legal state deliberately unchanged.
    after = mutate_case(case_dir, "liveness_observed", update)
    return {**record, "case_status_after_probe": after["status"]}


def patrol(brand_dir: Path, keywords: list[str]) -> dict:
    results, errors = [], []
    for child in sorted((brand_dir / "cases").iterdir()):
        if not child.is_dir():
            continue
        try:
            results.append(probe_case(child, keywords))
        except (ValueError, OSError, KeyError) as exc:
            errors.append({"case_dir": str(child), "error": str(exc)})
    failed_targets = sum(bool(t.get("error")) for result in results for t in result["targets"])
    return {"results": results, "errors": errors, "probed_count": len(results), "failed_target_count": failed_targets}


def _main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH)
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("probe", "patrol"):
        p = sub.add_parser(name); p.add_argument("--slug", required=True)
        if name == "probe":
            p.add_argument("--case-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    directory, profile = load_brand_profile(args.slug, args.registry)
    keywords = profile.get("keyword_watch_patterns") or [profile["brand_name"]]
    if args.cmd == "probe":
        assert_case_brand(args.case_dir, directory)
        result = probe_case(args.case_dir, keywords)
    else:
        result = patrol(directory, keywords)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(bool(result.get("errors")) or bool(result.get("failed_target_count")) or any(t.get("error") for t in result.get("targets", [])))


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr); sys.exit(2)
