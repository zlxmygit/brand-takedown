from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from brand_registry import (
    is_allowlisted_url,
    load_brand_profile,
    normalize_hostname,
    sanitize_http_url,
)

CASE_STATUSES = (
    "DISCOVERED",
    "EVIDENCE_LOCKED",
    "STRIKE_READY",
    "ACTIVE_ENFORCEMENT",
    "COUNTER_NOTICE_ALERT",
    "TAKEN_DOWN",
    "WATCHLIST_RESURRECTION",
)

CHANNEL_CLASSES = ("ENFORCEMENT_SLA", "REGULATORY_FILING")

CHANNEL_STATUSES = (
    "PENDING_SUBMISSION",
    "DRAFT_CREATED",
    "SUBMITTED",
    "ACKNOWLEDGED",
    "NEED_MORE_INFO",
    "SLA_BREACHED",
    "ESCALATED_TIER2",
    "ESCALATED_TIER3",
    "RESOLVED",
    "REJECTED",
)

ACTIVE_SLA_CHANNEL_STATUSES = (
    "SUBMITTED",
    "ACKNOWLEDGED",
    "SLA_BREACHED",
    "ESCALATED_TIER2",
    "ESCALATED_TIER3",
)

DEFAULT_SLA_HOURS = {
    "payment": 48,
    "saas": 48,
    "phishing": 48,
    "registrar": 72,
    "hosting": 72,
    "cdn": 72,
    "esp": 72,
    "search_ads": 120,
}

ISO_FRAC_RE = re.compile(r"\.(\d+)")
ISO_COLONLESS_TZ_RE = re.compile(r"([+-])(\d{2})(\d{2})$")


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso_utc(value: str) -> datetime:
    cleaned = value.strip()
    if cleaned.endswith(("Z", "z")):
        cleaned = cleaned[:-1] + "+00:00"
    else:
        cleaned = ISO_COLONLESS_TZ_RE.sub(r"\1\2:\3", cleaned)
    cleaned = ISO_FRAC_RE.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), cleaned, count=1)
    dt = datetime.fromisoformat(cleaned)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _format_iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _add_business_days(start_dt: datetime, business_days: int) -> datetime:
    current = start_dt
    added = 0
    while added < business_days:
        current += timedelta(days=1)
        if current.weekday() < 5:
            added += 1
    return current


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp_path, path)


def _host_to_slug(host: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", host.lower()).strip("-")


def _find_existing_case_for_host(cases_root: Path, host: str) -> Path | None:
    if not cases_root.is_dir():
        return None
    for child in sorted(cases_root.iterdir()):
        case_file = child / "case.json"
        if not case_file.is_file():
            continue
        try:
            data = json.loads(case_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if data.get("primary_domain") == host:
            return child
    return None


def load_case(case_dir: Path) -> dict:
    case_file = case_dir / "case.json"
    if not case_file.exists():
        raise FileNotFoundError(f"case.json not found in {case_dir}")
    return json.loads(case_file.read_text(encoding="utf-8"))


def save_case(case_dir: Path, case_data: dict) -> dict:
    case_data["updated_at"] = _utc_now_iso()
    _atomic_write_json(case_dir / "case.json", case_data)
    return case_data


def create_case(
    brand_dir: Path,
    target_url: str,
    infringement_types: list[str],
    allowlist_domains: list[str],
    now_iso: str | None = None,
) -> tuple[Path, dict]:
    if is_allowlisted_url(target_url, allowlist_domains):
        raise ValueError(
            f"SAFETY ABORT: Target {target_url!r} matches brand allowlist {allowlist_domains!r}. Refusing case creation."
        )
    clean_url = sanitize_http_url(target_url)
    host = normalize_hostname(clean_url)
    if not host:
        raise ValueError(f"Cannot extract valid hostname from {target_url!r}")

    dt = _parse_iso_utc(now_iso or _utc_now_iso())
    ts = _format_iso_utc(dt)
    cases_root = brand_dir.expanduser().resolve() / "cases"
    cases_root.mkdir(parents=True, exist_ok=True)

    existing_dir = _find_existing_case_for_host(cases_root, host)
    if existing_dir is not None:
        data = load_case(existing_dir)
        urls = data.setdefault("target_urls", [])
        if clean_url not in urls:
            urls.append(clean_url)
        types = data.setdefault("infringement_types", [])
        for itype in infringement_types:
            if itype not in types:
                types.append(itype)
        data["updated_at"] = ts
        _atomic_write_json(existing_dir / "case.json", data)
        return existing_dir, data

    case_id = f"CASE-{dt.strftime('%Y%m%d')}-{_host_to_slug(host)}"
    case_dir = cases_root / case_id
    (case_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (case_dir / "packets").mkdir(parents=True, exist_ok=True)

    unique_types: list[str] = []
    for itype in infringement_types:
        if itype not in unique_types:
            unique_types.append(itype)

    case_data = {
        "case_id": case_id,
        "primary_domain": host,
        "target_urls": [clean_url],
        "status": "DISCOVERED",
        "infringement_types": unique_types,
        "infrastructure_baseline": {
            "ips": [],
            "nameservers": [],
            "registrar": "",
            "registrar_iana_id": "",
            "registrar_abuse_emails": [],
            "saas_platform": "",
            "saas_shop_id": "",
        },
        "linked_payment_cloak_domains": [],
        "channels": [],
        "counter_notices": [],
        "created_at": ts,
        "updated_at": ts,
    }
    _atomic_write_json(case_dir / "case.json", case_data)
    return case_dir, case_data


def _compute_channel_timestamps(
    channel_class: str,
    category: str,
    status: str,
    sla_hours: int | None,
    submitted_at: str | None,
    existing: dict | None,
) -> tuple[int | None, str, str, str]:
    prior_tier = int(existing.get("escalation_tier", 1)) if existing else 1
    prior_status = str(existing.get("status", "")) if existing else ""
    prior_sub = str(existing.get("submitted_at", "")).strip() if existing else ""
    prior_due = str(existing.get("next_action_due_at", "")).strip() if existing else ""

    if prior_tier >= 2 and status == "ACKNOWLEDGED" and prior_status in ("ESCALATED_TIER2", "ESCALATED_TIER3"):
        effective_status = prior_status
    else:
        effective_status = status

    if channel_class != "ENFORCEMENT_SLA":
        norm_sub = _format_iso_utc(_parse_iso_utc(submitted_at)) if submitted_at else prior_sub
        if not norm_sub and effective_status == "SUBMITTED":
            norm_sub = _utc_now_iso()
        return None, effective_status, norm_sub, ""

    effective_sla = (
        sla_hours
        if sla_hours is not None
        else (existing.get("sla_hours") if existing and existing.get("sla_hours") else DEFAULT_SLA_HOURS.get(category, 72))
    )

    if effective_status in ("RESOLVED", "REJECTED"):
        norm_sub = _format_iso_utc(_parse_iso_utc(submitted_at)) if submitted_at else prior_sub
        return int(effective_sla), effective_status, norm_sub, ""

    if submitted_at:
        norm_sub = _format_iso_utc(_parse_iso_utc(submitted_at))
    elif prior_sub:
        norm_sub = prior_sub
    elif effective_status in ACTIVE_SLA_CHANNEL_STATUSES:
        norm_sub = _utc_now_iso()
    else:
        norm_sub = ""

    if prior_tier >= 2 and prior_due and not submitted_at:
        next_due = prior_due
    elif norm_sub and effective_status in ACTIVE_SLA_CHANNEL_STATUSES:
        if prior_due and not submitted_at and sla_hours is None:
            next_due = prior_due
        else:
            next_due = _format_iso_utc(_parse_iso_utc(norm_sub) + timedelta(hours=int(effective_sla)))
    else:
        next_due = ""

    return int(effective_sla), effective_status, norm_sub, next_due


def upsert_channel(
    case_dir: Path,
    channel_id: str,
    channel_class: str,
    category: str,
    provider_name: str,
    target_endpoint: str,
    status: str = "PENDING_SUBMISSION",
    sla_hours: int | None = None,
    ticket_ref: str = "",
    submitted_at: str | None = None,
) -> dict:
    if channel_class not in CHANNEL_CLASSES:
        raise ValueError(f"channel_class must be one of {CHANNEL_CLASSES}, got {channel_class!r}")
    if status not in CHANNEL_STATUSES:
        raise ValueError(f"status must be one of {CHANNEL_STATUSES}, got {status!r}")

    data = load_case(case_dir)
    channels: list[dict] = data.setdefault("channels", [])
    existing: dict | None = next((c for c in channels if c.get("channel_id") == channel_id), None)

    effective_sla, effective_status, norm_sub, next_due = _compute_channel_timestamps(
        channel_class=channel_class,
        category=category,
        status=status,
        sla_hours=sla_hours,
        submitted_at=submitted_at,
        existing=existing,
    )

    if existing is None:
        record = {
            "channel_id": channel_id,
            "channel_class": channel_class,
            "category": category,
            "provider_name": provider_name,
            "target_endpoint": target_endpoint,
            "status": effective_status,
            "ticket_ref": ticket_ref,
            "escalation_tier": 1,
            "sla_hours": effective_sla,
            "submitted_at": norm_sub,
            "next_action_due_at": next_due,
            "history": [],
        }
        channels.append(record)
    else:
        existing["channel_class"] = channel_class
        existing["category"] = category
        existing["provider_name"] = provider_name
        existing["target_endpoint"] = target_endpoint
        existing["status"] = effective_status
        if ticket_ref:
            existing["ticket_ref"] = ticket_ref
        existing["sla_hours"] = effective_sla
        existing["submitted_at"] = norm_sub
        existing["next_action_due_at"] = next_due

    if effective_status in ACTIVE_SLA_CHANNEL_STATUSES and data.get("status") in (
        "DISCOVERED",
        "EVIDENCE_LOCKED",
        "STRIKE_READY",
    ):
        data["status"] = "ACTIVE_ENFORCEMENT"

    return save_case(case_dir, data)


def update_channel_fields(
    case_dir: Path,
    channel_id: str,
    status: str | None = None,
    ticket_ref: str | None = None,
    submitted_at: str | None = None,
    sla_hours: int | None = None,
) -> dict:
    data = load_case(case_dir)
    existing: dict | None = next((c for c in data.get("channels", []) if c.get("channel_id") == channel_id), None)
    if existing is None:
        raise KeyError(f"Channel {channel_id!r} not found in {case_dir}")

    target_status = status if status is not None else existing["status"]
    if target_status not in CHANNEL_STATUSES:
        raise ValueError(f"Invalid channel status: {target_status!r}")

    effective_sla, effective_status, norm_sub, next_due = _compute_channel_timestamps(
        channel_class=existing["channel_class"],
        category=existing["category"],
        status=target_status,
        sla_hours=sla_hours,
        submitted_at=submitted_at,
        existing=existing,
    )
    existing["status"] = effective_status
    existing["sla_hours"] = effective_sla
    existing["submitted_at"] = norm_sub
    existing["next_action_due_at"] = next_due
    if ticket_ref is not None and ticket_ref.strip():
        existing["ticket_ref"] = ticket_ref.strip()

    if effective_status in ACTIVE_SLA_CHANNEL_STATUSES and data.get("status") in (
        "DISCOVERED",
        "EVIDENCE_LOCKED",
        "STRIKE_READY",
    ):
        data["status"] = "ACTIVE_ENFORCEMENT"

    return save_case(case_dir, data)


def add_linked_cloak_domain(
    case_dir: Path,
    cloak_domain: str,
    role: str = "payment_b_site",
    allowlist_domains: list[str] | None = None,
) -> dict:
    if allowlist_domains and is_allowlisted_url(cloak_domain, allowlist_domains):
        raise ValueError(
            f"SAFETY ABORT: Linked cloak domain {cloak_domain!r} matches brand allowlist {allowlist_domains!r}."
        )
    if "://" in cloak_domain:
        sanitize_http_url(cloak_domain)
    host = normalize_hostname(cloak_domain)
    if not host:
        raise ValueError(f"Invalid cloak domain: {cloak_domain!r}")
    data = load_case(case_dir)
    linked: list[dict] = data.setdefault("linked_payment_cloak_domains", [])
    for entry in linked:
        if entry.get("domain") == host:
            return data
    linked.append(
        {
            "domain": host,
            "role": role,
            "discovered_at": _utc_now_iso(),
        }
    )
    return save_case(case_dir, data)


def scan_due_escalations(brand_dir: Path, now_iso: str | None = None) -> list[dict]:
    now_dt = _parse_iso_utc(now_iso or _utc_now_iso())
    cases_root = brand_dir.expanduser().resolve() / "cases"
    due_items: list[dict] = []
    if not cases_root.is_dir():
        return due_items

    inactive_case_statuses = {"TAKEN_DOWN", "WATCHLIST_RESURRECTION"}
    eligible_channel_statuses = {"SUBMITTED", "ACKNOWLEDGED", "SLA_BREACHED", "ESCALATED_TIER2"}

    for child in sorted(cases_root.iterdir()):
        case_file = child / "case.json"
        if not case_file.is_file():
            continue
        case_data = load_case(child)
        if case_data.get("status") in inactive_case_statuses:
            continue
        for ch in case_data.get("channels", []):
            if ch.get("channel_class") != "ENFORCEMENT_SLA":
                continue
            if ch.get("status") not in eligible_channel_statuses:
                continue
            due_str = str(ch.get("next_action_due_at", "")).strip()
            if not due_str:
                continue
            due_dt = _parse_iso_utc(due_str)
            if now_dt >= due_dt:
                tier2_ts = ""
                for hist in ch.get("history", []):
                    if hist.get("event") == "escalated_to_tier_2":
                        tier2_ts = str(hist.get("timestamp", ""))
                due_items.append(
                    {
                        "case_id": case_data["case_id"],
                        "case_dir": str(child),
                        "primary_domain": case_data["primary_domain"],
                        "channel_id": ch["channel_id"],
                        "provider_name": ch["provider_name"],
                        "target_endpoint": ch["target_endpoint"],
                        "current_tier": ch.get("escalation_tier", 1),
                        "ticket_ref": ch.get("ticket_ref", ""),
                        "submitted_at": ch.get("submitted_at", ""),
                        "tier2_escalated_at": tier2_ts,
                        "next_action_due_at": due_str,
                    }
                )
    return due_items


def advance_escalation_tier(
    case_dir: Path,
    channel_id: str,
    now_iso: str | None = None,
    next_sla_hours: int = 48,
) -> dict:
    now_dt = _parse_iso_utc(now_iso or _utc_now_iso())
    ts = _format_iso_utc(now_dt)
    data = load_case(case_dir)
    target_ch: dict | None = next((c for c in data.get("channels", []) if c.get("channel_id") == channel_id), None)
    if target_ch is None:
        raise KeyError(f"Channel {channel_id!r} not found in {case_dir}")
    if target_ch.get("channel_class") != "ENFORCEMENT_SLA":
        raise ValueError(f"Channel {channel_id!r} is {target_ch.get('channel_class')}, cannot escalate SLA")

    current_tier = int(target_ch.get("escalation_tier", 1))
    new_tier = min(current_tier + 1, 3)
    target_ch["escalation_tier"] = new_tier
    target_ch["status"] = "ESCALATED_TIER2" if new_tier == 2 else "ESCALATED_TIER3"
    target_ch["next_action_due_at"] = _format_iso_utc(now_dt + timedelta(hours=next_sla_hours))
    target_ch.setdefault("history", []).append(
        {
            "event": f"escalated_to_tier_{new_tier}",
            "timestamp": ts,
        }
    )
    return save_case(case_dir, data)


def record_counter_notice(
    case_dir: Path,
    channel_id: str,
    received_at_iso: str,
    summary: str,
) -> dict:
    recv_dt = _parse_iso_utc(received_at_iso)
    deadline_dt = _add_business_days(recv_dt, 10)
    data = load_case(case_dir)
    data["status"] = "COUNTER_NOTICE_ALERT"
    data.setdefault("counter_notices", []).append(
        {
            "channel_id": channel_id,
            "received_at_iso": _format_iso_utc(recv_dt),
            "legal_action_deadline_iso": _format_iso_utc(deadline_dt),
            "summary": summary,
            "recommended_actions": [
                "Verify physical address and federal court jurisdiction consent in counter-notice for perjury/bad-faith.",
                "Pivot immediately to non-DMCA lanes: Registered Trademark Counterfeit, Design Patent, and Payment Processor Fraud.",
            ],
        }
    )
    return save_case(case_dir, data)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Persistent takedown case & SLA state machine.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="Create or merge an infringement case for a brand")
    p_create.add_argument("--slug", required=True)
    p_create.add_argument("--url", required=True)
    p_create.add_argument("--types", nargs="+", required=True)

    p_ch = sub.add_parser("add-channel", help="Add or replace a takedown channel on a case")
    p_ch.add_argument("--case-dir", type=Path, required=True)
    p_ch.add_argument("--channel-id", required=True)
    p_ch.add_argument("--channel-class", choices=CHANNEL_CLASSES, required=True)
    p_ch.add_argument("--category", required=True)
    p_ch.add_argument("--provider", required=True)
    p_ch.add_argument("--endpoint", required=True)
    p_ch.add_argument("--status", choices=CHANNEL_STATUSES, default="PENDING_SUBMISSION")
    p_ch.add_argument("--sla-hours", type=int, default=None)
    p_ch.add_argument("--ticket-ref", default="")
    p_ch.add_argument("--submitted-at", default=None)

    p_upd = sub.add_parser("update-channel", help="Update status or ticket reference of an existing channel")
    p_upd.add_argument("--case-dir", type=Path, required=True)
    p_upd.add_argument("--channel-id", required=True)
    p_upd.add_argument("--status", choices=CHANNEL_STATUSES, default=None)
    p_upd.add_argument("--ticket-ref", default=None)
    p_upd.add_argument("--submitted-at", default=None)
    p_upd.add_argument("--sla-hours", type=int, default=None)

    p_esc = sub.add_parser("escalate", help="Advance an overdue ENFORCEMENT_SLA channel to next tier")
    p_esc.add_argument("--case-dir", type=Path, required=True)
    p_esc.add_argument("--channel-id", required=True)
    p_esc.add_argument("--next-sla-hours", type=int, default=48)

    p_cloak = sub.add_parser("add-cloak", help="Link a payment B-site / cloak domain discovered during checkout probe")
    p_cloak.add_argument("--slug", default=None, help="Optional brand slug to enforce allowlist guard")
    p_cloak.add_argument("--case-dir", type=Path, required=True)
    p_cloak.add_argument("--domain", required=True)
    p_cloak.add_argument("--role", default="payment_b_site")

    p_cn = sub.add_parser("counter-notice", help="Record a P0 DMCA counter-notice and compute 10-business-day deadline")
    p_cn.add_argument("--case-dir", type=Path, required=True)
    p_cn.add_argument("--channel-id", required=True)
    p_cn.add_argument("--received-at", required=True)
    p_cn.add_argument("--summary", required=True)

    p_due = sub.add_parser("due", help="List all SLA-breached channels requiring chaser or upstream escalation")
    p_due.add_argument("--slug", required=True)

    p_sum = sub.add_parser("summary", help="Print status summary of all cases for a brand")
    p_sum.add_argument("--slug", required=True)

    args = parser.parse_args(argv)

    if args.cmd == "create":
        brand_dir, prof = load_brand_profile(args.slug)
        cdir, cdata = create_case(brand_dir, args.url, args.types, prof.get("allowlist_domains", []))
        print(json.dumps({"case_dir": str(cdir), "case": cdata}, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "add-channel":
        updated = upsert_channel(
            args.case_dir,
            channel_id=args.channel_id,
            channel_class=args.channel_class,
            category=args.category,
            provider_name=args.provider,
            target_endpoint=args.endpoint,
            status=args.status,
            sla_hours=args.sla_hours,
            ticket_ref=args.ticket_ref,
            submitted_at=args.submitted_at,
        )
        print(json.dumps(updated, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "update-channel":
        updated = update_channel_fields(
            args.case_dir,
            channel_id=args.channel_id,
            status=args.status,
            ticket_ref=args.ticket_ref,
            submitted_at=args.submitted_at,
            sla_hours=args.sla_hours,
        )
        print(json.dumps(updated, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "escalate":
        updated = advance_escalation_tier(args.case_dir, args.channel_id, next_sla_hours=args.next_sla_hours)
        print(json.dumps(updated, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "add-cloak":
        allow: list[str] | None = None
        if args.slug:
            _, prof = load_brand_profile(args.slug)
            allow = prof.get("allowlist_domains", [])
        elif args.case_dir.expanduser().resolve().parent.parent.joinpath("profile.json").is_file():
            p_json = json.loads(
                args.case_dir.expanduser().resolve().parent.parent.joinpath("profile.json").read_text(encoding="utf-8")
            )
            allow = p_json.get("allowlist_domains", [])
        updated = add_linked_cloak_domain(args.case_dir, args.domain, role=args.role, allowlist_domains=allow)
        print(json.dumps(updated, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "counter-notice":
        updated = record_counter_notice(args.case_dir, args.channel_id, args.received_at, args.summary)
        print(json.dumps(updated, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "due":
        brand_dir, _ = load_brand_profile(args.slug)
        due = scan_due_escalations(brand_dir)
        print(json.dumps({"due_count": len(due), "due_channels": due}, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "summary":
        brand_dir, _ = load_brand_profile(args.slug)
        cases_root = brand_dir / "cases"
        rows = []
        if cases_root.is_dir():
            for child in sorted(cases_root.iterdir()):
                if (child / "case.json").is_file():
                    d = load_case(child)
                    rows.append(
                        {
                            "case_id": d["case_id"],
                            "primary_domain": d["primary_domain"],
                            "status": d["status"],
                            "channel_count": len(d.get("channels", [])),
                            "counter_notices": len(d.get("counter_notices", [])),
                        }
                    )
        print(json.dumps({"total_cases": len(rows), "cases": rows}, ensure_ascii=False, indent=2))
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(_main())
