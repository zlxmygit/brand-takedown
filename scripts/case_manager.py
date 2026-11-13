"""Brand-bound case state with optimistic revisions and separate legal tasks."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import uuid
from zoneinfo import ZoneInfo

from brand_registry import (DEFAULT_REGISTRY_PATH, check_target, load_brand_profile,
                            normalize_hostname, profile_from_dir, utc_now)
from storage import ConflictError, atomic_write_json, locked, private_dir, read_json, safe_path

CASE_STATUSES = ("DISCOVERED", "EVIDENCE_LOCKED", "STRIKE_READY", "ACTIVE_ENFORCEMENT", "COUNTER_NOTICE_ALERT", "TAKEN_DOWN", "WATCHLIST_RESURRECTION")
INFRINGING_TYPES = ("COPYRIGHT_CLONE", "TRADEMARK_IMPERSONATION", "COUNTERFEIT_GOODS", "DESIGN_PATENT_COPY", "PHISHING_OR_FAKE_TRACKING")
CHANNEL_CLASSES = ("ENFORCEMENT_SLA", "REGULATORY_FILING")
CHANNEL_STATUSES = ("PENDING_SUBMISSION", "DRAFT_CREATED", "SUBMITTED", "ACKNOWLEDGED", "NEED_MORE_INFO", "SLA_BREACHED", "ESCALATED_TIER2", "ESCALATED_TIER3", "RESOLVED", "REJECTED")
ACTIVE_SLA_CHANNEL_STATUSES = ("SUBMITTED", "ACKNOWLEDGED", "NEED_MORE_INFO", "SLA_BREACHED", "ESCALATED_TIER2", "ESCALATED_TIER3")
DEFAULT_SLA_HOURS = {"payment": 48, "saas": 48, "phishing": 48, "registrar": 72, "hosting": 72, "cdn": 72, "esp": 72, "search_ads": 120}
_atomic_write_json = atomic_write_json
_utc_now_iso = utc_now


def _parse_iso_utc(value: str) -> datetime:
    value = value.strip().replace("z", "Z")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _format_iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _add_business_days(start_dt: datetime, count: int) -> datetime:
    # Weekend-only estimate, never a certified statutory deadline.
    result = start_dt
    for _ in range(count):
        result += timedelta(days=1)
        while result.weekday() >= 5:
            result += timedelta(days=1)
    return result


def case_profile(case_dir: Path) -> dict:
    case_dir = safe_path(case_dir)
    if case_dir.parent.name != "cases":
        raise ValueError("Case must be directly inside its brand's cases directory")
    return profile_from_dir(case_dir.parent.parent)


def load_case(case_dir: Path) -> dict:
    case_dir = safe_path(case_dir)
    profile = case_profile(case_dir)
    data = read_json(case_dir / "case.json")
    if (data.get("schema_version") != 2 or data.get("brand_id") != profile["brand_id"]
            or data.get("brand_slug") != profile["brand_slug"] or data.get("case_id") != case_dir.name):
        raise ConflictError("Case identity mismatch or legacy schema; reviewed migration required")
    if not isinstance(data.get("revision"), int) or data["revision"] < 0:
        raise ValueError("Invalid case revision")
    urls = data.get("target_urls")
    if not isinstance(urls, list) or not urls:
        raise ValueError("Case has no targets")
    from brand_registry import sanitize_http_url
    for url in urls:
        if sanitize_http_url(url) != url or normalize_hostname(url) != data["primary_domain"]:
            raise ConflictError("Case target identity mismatch")
    return data


def assert_case_brand(case_dir: Path, brand_dir: Path) -> None:
    if safe_path(case_dir).parent != safe_path(brand_dir) / "cases":
        raise ConflictError("--slug and --case-dir belong to different brands")
    load_case(case_dir)


def _persist(case_dir: Path, data: dict, event: str) -> dict:
    data["revision"] += 1
    data["updated_at"] = utc_now()
    data.setdefault("history", []).append({"event": event, "timestamp": data["updated_at"], "revision": data["revision"]})
    # The derived alert cannot be cleared by a network probe or unrelated channel action.
    if any(task.get("status") == "OPEN" for task in data.get("counter_notices", [])):
        data["status"] = "COUNTER_NOTICE_ALERT"
    atomic_write_json(case_dir / "case.json", data)
    return data


def mutate_case(case_dir: Path, event: str, mutation) -> dict:
    case_dir = safe_path(case_dir)
    with locked(case_dir.parent.parent / ".brand.lock"), locked(case_dir / ".case.lock"):
        data = load_case(case_dir)
        mutation(data)
        return _persist(case_dir, data, event)


def save_case(case_dir: Path, case_data: dict) -> dict:
    case_dir = safe_path(case_dir)
    with locked(case_dir.parent.parent / ".brand.lock"), locked(case_dir / ".case.lock"):
        current = load_case(case_dir)
        if case_data.get("revision") != current["revision"]:
            raise ConflictError("Stale revision; reload before updating")
        for key in set(current) | set(case_data):
            if key in ("notes", "user_tags"):
                continue
            if case_data.get(key) != current.get(key):
                raise ConflictError(f"Use a dedicated operation to modify {key}")
        return _persist(case_dir, case_data, "manual_update")


def create_case(brand_dir: Path, target_url: str, infringement_types: list[str],
                allowlist_domains: list[str] | None = None, now_iso: str | None = None) -> tuple[Path, dict]:
    brand_dir = safe_path(brand_dir)
    profile = profile_from_dir(brand_dir)
    url = check_target(target_url, profile)
    if allowlist_domains:
        from brand_registry import is_allowlisted_url
        if is_allowlisted_url(url, allowlist_domains):
            raise ValueError("Target matches additional allowlist")
    if not infringement_types or any(t not in INFRINGING_TYPES for t in infringement_types):
        raise ValueError("Unsupported infringement type")
    host = normalize_hostname(url)
    timestamp = _format_iso_utc(_parse_iso_utc(now_iso or utc_now()))
    root = private_dir(brand_dir / "cases")
    with locked(brand_dir / ".brand.lock"):
        for child in sorted(root.iterdir()):
            if not child.is_dir():
                continue
            if not (child / "case.json").exists():
                raise ValueError(f"Incomplete case requires recovery review: {child.name}")
            old = load_case(child)
            if old["primary_domain"] == host:
                def merge(data):
                    if url not in data["target_urls"]:
                        data["target_urls"].append(url)
                        if data.get("liveness_review", {}).get("decision") == "DOWN":
                            data["liveness_state"] = "SCOPE_CHANGED_REVIEW"
                    data["infringement_types"] = sorted(set(data["infringement_types"] + infringement_types))
                return child, mutate_case(child, "target_merged", merge)
        case_id = "CASE-" + uuid.uuid4().hex
        case_dir = root / case_id
        case_dir.mkdir(mode=0o700, exist_ok=False)
        private_dir(case_dir / "evidence")
        private_dir(case_dir / "packets")
        data = {"schema_version": 2, "revision": 0, "brand_id": profile["brand_id"], "brand_slug": profile["brand_slug"],
                "case_id": case_id, "primary_domain": host, "target_urls": [url], "status": "DISCOVERED",
                "liveness_state": "UNKNOWN", "infringement_types": sorted(set(infringement_types)),
                "infrastructure_baseline": {"ips": []}, "linked_payment_cloak_domains": [], "channels": [],
                "counter_notices": [], "captures": [], "history": [], "created_at": timestamp, "updated_at": timestamp}
        atomic_write_json(case_dir / "case.json", data)
        return case_dir, data


def _hours(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 8760:
        raise ValueError("Follow-up hours must be 1..8760")
    return value


def _channel(data: dict, channel_id: str) -> dict:
    for channel in data["channels"]:
        if channel["channel_id"] == channel_id:
            return channel
    raise KeyError(f"Unknown channel: {channel_id}")


def upsert_channel(case_dir: Path, channel_id: str, channel_class: str, category: str,
                   provider_name: str, target_endpoint: str, status="PENDING_SUBMISSION",
                   sla_hours=None, ticket_ref="", submitted_at=None) -> dict:
    if channel_class not in CHANNEL_CLASSES or status not in ("PENDING_SUBMISSION", "DRAFT_CREATED") or submitted_at:
        raise ValueError("Register a draft channel; confirm actual transmission with submit")
    if not all(isinstance(v, str) and v.strip() for v in (channel_id, category, provider_name, target_endpoint)):
        raise ValueError("Channel identity and endpoint are required")
    hours = _hours(sla_hours if sla_hours is not None else DEFAULT_SLA_HOURS.get(category, 72))
    def update(data):
        existing = next((c for c in data["channels"] if c["channel_id"] == channel_id), None)
        if existing and existing.get("submitted_at"):
            raise ConflictError("Submitted channel identity is immutable; add a new channel")
        record = {"channel_id": channel_id, "channel_class": channel_class, "category": category,
                  "provider_name": provider_name, "target_endpoint": target_endpoint, "status": status,
                  "ticket_ref": ticket_ref, "escalation_tier": 1, "sla_hours": hours if channel_class == "ENFORCEMENT_SLA" else None,
                  "submitted_at": "", "next_action_due_at": "", "history": []}
        if existing:
            data["channels"].remove(existing)
        data["channels"].append(record)
    return mutate_case(case_dir, "channel_draft_registered", update)


def open_legal_tasks(data: dict, channel_id: str) -> list[dict]:
    return [t for t in data.get("counter_notices", [])
            if t.get("status") == "OPEN" and t.get("channel_id") == channel_id]


def submission_context(data: dict, channel: dict, request: dict) -> tuple[str, int]:
    """One policy for preparation, approval, export and receipt registration."""
    kind = request.get("submission_kind")
    if kind is None:
        kind = ("INITIAL" if not channel["submitted_at"] else
                "SUPPLEMENT" if channel["status"] == "NEED_MORE_INFO" else
                "ESCALATION" if channel.get("pending_tier") else "INITIAL")
    if kind not in ("INITIAL", "SUPPLEMENT", "ESCALATION", "COUNTER_NOTICE_RESPONSE"):
        raise ValueError("Unknown submission_kind")
    tasks = open_legal_tasks(data, channel["channel_id"])
    if kind == "COUNTER_NOTICE_RESPONSE":
        task = next((t for t in tasks if t["task_id"] == request.get("legal_task_id")), None)
        if task is None:
            raise ConflictError("Response requires an open legal task on this channel")
        if request.get("response_source_ref") != task["source_ref"]:
            raise ConflictError("Response source differs from the recorded counter-notice")
        for field in ("response_text", "response_reviewed_by", "response_source_ref"):
            if not isinstance(request.get(field), str) or not request[field].strip():
                raise ValueError(f"Counter-notice response requires {field}")
        return kind, channel["escalation_tier"]
    if tasks:
        raise ConflictError("Channel paused for an open counter-notice; use a reviewed COUNTER_NOTICE_RESPONSE")
    if kind == "INITIAL":
        if channel["submitted_at"]:
            raise ConflictError("Initial transmission already recorded; select supplement or plan escalation")
        return kind, 1
    if not channel["submitted_at"]:
        raise ConflictError("Follow-up requires an initial transmission")
    if kind == "SUPPLEMENT":
        if channel["status"] != "NEED_MORE_INFO":
            raise ConflictError("Supplement requires a recorded provider request for more information")
        expected_ref = channel.get("ticket_ref") or next(
            (h["submission_ref"] for h in reversed(channel["history"]) if h.get("event") == "transmission_recorded"), "")
        if not expected_ref or request.get("thread_ref", expected_ref) != expected_ref:
            raise ConflictError("Supplement must reference the current provider ticket or transmission")
        if request.get("supplement_cycle", channel.get("supplement_cycle", 0)) != channel.get("supplement_cycle", 0):
            raise ConflictError("Supplement request changed; prepare a new packet")
        return kind, channel["escalation_tier"]
    if not channel.get("pending_tier") or channel["status"] == "NEED_MORE_INFO":
        raise ConflictError("Escalation requires a due, planned escalation draft")
    return kind, channel["pending_tier"]


def confirm_submission(case_dir: Path, channel_id: str, packet_id: str, submission_ref: str, sent_at: str) -> dict:
    if not isinstance(submission_ref, str) or not submission_ref.strip():
        raise ValueError("Actual transmission receipt/reference required")
    receipt = submission_ref.strip()
    sent = _parse_iso_utc(sent_at)
    if sent > datetime.now(timezone.utc) + timedelta(minutes=5):
        raise ValueError("Transmission timestamp is in the future")
    def submit(data):
        from packets import verify_approved_packet
        channel = _channel(data, channel_id)
        if any(h.get("packet_id") == packet_id or h.get("submission_ref") == receipt for h in channel["history"]):
            raise ConflictError("Packet or transmission receipt already recorded")
        packet = verify_approved_packet(case_dir, packet_id)
        if packet["channel_id"] != channel_id or packet["endpoint"] != channel["target_endpoint"]:
            raise ConflictError("Approval does not match this channel")
        if channel["status"] in ("RESOLVED", "REJECTED") and packet["request"].get("submission_kind") != "COUNTER_NOTICE_RESPONSE":
            raise ConflictError("Closed channel cannot be submitted")
        kind, tier = submission_context(data, channel, packet["request"])
        if kind == "ESCALATION" and sent < _parse_iso_utc(channel["next_action_due_at"]):
            raise ConflictError("Escalation transmission predates the follow-up window")
        if sent < _parse_iso_utc(packet["approval"]["approved_at"]):
            raise ConflictError("Transmission predates approval; review historical import separately")
        if packet["tier"] != tier or packet.get("submission_kind", kind) != kind:
            raise ConflictError("Packet purpose or tier differs from planned submission")
        event = {"event": "transmission_recorded", "kind": kind, "tier": tier, "packet_id": packet_id,
                 "submission_ref": receipt, "timestamp": _format_iso_utc(sent)}
        if kind == "COUNTER_NOTICE_RESPONSE":
            event["legal_task_id"] = packet["request"]["legal_task_id"]
            task = next(t for t in data["counter_notices"] if t["task_id"] == event["legal_task_id"])
            task.setdefault("responses", []).append(dict(event))
            # A response neither resolves the task nor restarts normal follow-ups.
        else:
            if not channel["submitted_at"]:
                channel["submitted_at"] = _format_iso_utc(sent)
            channel["escalation_tier"] = tier
            channel["status"] = "SUBMITTED" if tier == 1 else f"ESCALATED_TIER{tier}"
            if channel["channel_class"] == "ENFORCEMENT_SLA":
                hours = channel.pop("pending_hours", channel["sla_hours"]) if kind == "ESCALATION" else channel.get("followup_hours", channel["sla_hours"])
                channel["followup_hours"] = hours
                channel["next_action_due_at"] = _format_iso_utc(sent + timedelta(hours=hours))
            channel.pop("pending_tier", None)
            channel.pop("pending_hours", None)
            if kind == "SUPPLEMENT":
                event["thread_ref"] = packet["request"]["thread_ref"]
                event["supplement_cycle"] = packet["request"]["supplement_cycle"]
            data["status"] = "ACTIVE_ENFORCEMENT"
        channel["history"].append(event)
    return mutate_case(case_dir, "transmission_recorded", submit)


def update_channel_fields(case_dir: Path, channel_id: str, status=None, ticket_ref=None, submitted_at=None, sla_hours=None) -> dict:
    if submitted_at or sla_hours is not None:
        raise ValueError("Transmission timestamps and follow-up windows cannot be rewritten")
    if status is not None and status not in ("ACKNOWLEDGED", "NEED_MORE_INFO", "RESOLVED", "REJECTED"):
        raise ValueError("Invalid feedback status")
    def update(data):
        channel = _channel(data, channel_id)
        if status and not channel["submitted_at"]:
            raise ConflictError("Cannot acknowledge an unsubmitted channel")
        if channel["status"] in ("RESOLVED", "REJECTED") and status not in (None, channel["status"]):
            raise ConflictError("Closed channel requires a new reviewed channel")
        if status:
            channel["status"] = status
            if status in ("RESOLVED", "REJECTED"):
                channel["next_action_due_at"] = ""
            elif status == "NEED_MORE_INFO":
                channel["supplement_cycle"] = channel.get("supplement_cycle", 0) + 1
                channel.pop("pending_tier", None)
                channel.pop("pending_hours", None)
                if channel["channel_class"] == "ENFORCEMENT_SLA" and not open_legal_tasks(data, channel_id):
                    channel["next_action_due_at"] = utc_now()
                elif channel.get("legal_pause"):
                    channel["legal_pause"]["remaining_seconds"] = 0
        if ticket_ref:
            channel["ticket_ref"] = ticket_ref.strip()
        channel["history"].append({"event": "feedback", "status": channel["status"], "timestamp": utc_now()})
    return mutate_case(case_dir, "channel_feedback", update)


def add_linked_cloak_domain(case_dir: Path, cloak_domain: str, role="payment_b_site", allowlist_domains=None) -> dict:
    profile = case_profile(case_dir)
    url = check_target(cloak_domain if "://" in cloak_domain else "https://" + cloak_domain + "/", profile)
    host = normalize_hostname(url)
    def update(data):
        if not any(item["domain"] == host for item in data["linked_payment_cloak_domains"]):
            data["linked_payment_cloak_domains"].append({"domain": host, "role": role, "status": "UNVERIFIED_LEAD", "discovered_at": utc_now()})
            if data.get("liveness_review", {}).get("decision") == "DOWN":
                data["liveness_state"] = "SCOPE_CHANGED_REVIEW"
    return mutate_case(case_dir, "linked_lead_added", update)


def scan_due_escalations(brand_dir: Path, now_iso=None) -> list[dict]:
    now = _parse_iso_utc(now_iso or utc_now())
    items = []
    for child in sorted((safe_path(brand_dir) / "cases").iterdir()):
        if not child.is_dir():
            continue
        try:
            data = load_case(child)
            for task in data["counter_notices"]:
                if task["status"] == "OPEN":
                    items.append({"kind": "LEGAL_REVIEW", "case_id": data["case_id"], "case_dir": str(child), "task": task})
            for channel in data["channels"]:
                if open_legal_tasks(data, channel["channel_id"]):
                    continue
                if channel["channel_class"] == "REGULATORY_FILING" and channel["status"] == "NEED_MORE_INFO":
                    items.append({"kind": "SUPPLEMENT_REVIEW", "case_id": data["case_id"], "case_dir": str(child), **channel})
                    continue
                due = channel["next_action_due_at"]
                if (channel["channel_class"] == "ENFORCEMENT_SLA" and channel["status"] in ACTIVE_SLA_CHANNEL_STATUSES
                        and due and now >= _parse_iso_utc(due)):
                    kind = "SUPPLEMENT_REVIEW" if channel["status"] == "NEED_MORE_INFO" else "TIER3_REVIEW" if channel["escalation_tier"] == 3 else "FOLLOWUP_REVIEW"
                    items.append({"kind": kind, "case_id": data["case_id"], "case_dir": str(child), **channel})
        except (ValueError, OSError, KeyError) as exc:
            items.append({"kind": "CASE_ERROR", "case_dir": str(child), "error": str(exc)})
    return items


def advance_escalation_tier(case_dir: Path, channel_id: str, now_iso=None, next_sla_hours=48) -> dict:
    now = _parse_iso_utc(now_iso or utc_now())
    hours = _hours(next_sla_hours)
    def advance(data):
        channel = _channel(data, channel_id)
        if open_legal_tasks(data, channel_id):
            raise ConflictError("Channel paused for an open counter-notice")
        if channel["status"] == "NEED_MORE_INFO":
            raise ConflictError("Prepare a supplement before planning another escalation")
        if (channel["channel_class"] != "ENFORCEMENT_SLA" or channel["status"] not in ACTIVE_SLA_CHANNEL_STATUSES
                or not channel["submitted_at"] or not channel["next_action_due_at"]):
            raise ConflictError("Channel is not eligible for escalation")
        if now < _parse_iso_utc(channel["next_action_due_at"]):
            raise ConflictError("Internal follow-up window has not elapsed")
        if channel["escalation_tier"] >= 3 or channel.get("pending_tier"):
            raise ConflictError("No further automatic tier; review pending draft or Tier 3")
        channel["pending_tier"] = channel["escalation_tier"] + 1
        channel["pending_hours"] = hours
        # Planning a draft is not an actual transmission and must not reset deadlines.
    return mutate_case(case_dir, "escalation_draft_planned", advance)


def record_counter_notice(case_dir: Path, channel_id: str, received_at_iso: str, summary: str,
                          provider_received_at=None, provider_timezone="UTC", source_ref="") -> dict:
    received = _parse_iso_utc(received_at_iso)
    if not summary.strip() or not source_ref.strip():
        raise ValueError("Counter-notice summary and source message reference required")
    estimates = {}
    if provider_received_at:
        local = _parse_iso_utc(provider_received_at).astimezone(ZoneInfo(provider_timezone))
        estimates = {"earliest_restore_estimate": _format_iso_utc(_add_business_days(local, 10)),
                     "latest_restore_estimate": _format_iso_utc(_add_business_days(local, 14))}
    def record(data):
        channel = _channel(data, channel_id)
        if any(t["source_ref"] == source_ref and t["channel_id"] == channel_id for t in data["counter_notices"]):
            return
        if not open_legal_tasks(data, channel_id):
            now = _parse_iso_utc(utc_now())
            due = channel["next_action_due_at"]
            channel["legal_pause"] = {"started_at": _format_iso_utc(now), "previous_due_at": due,
                "remaining_seconds": max(0, (_parse_iso_utc(due) - now).total_seconds()) if due else None}
            channel["next_action_due_at"] = ""
        channel["legal_review_epoch"] = channel.get("legal_review_epoch", 0) + 1
        channel.pop("pending_tier", None)
        channel.pop("pending_hours", None)
        data["counter_notices"].append({"task_id": uuid.uuid4().hex, "status": "OPEN", "channel_id": channel_id,
            "received_by_rightsholder_at": _format_iso_utc(received), "provider_received_at": provider_received_at,
            "provider_timezone": provider_timezone, "source_ref": source_ref, "summary": summary,
            "review_due_at": utc_now(), "calendar_basis": "WEEKDAYS_ONLY_ESTIMATE_NOT_LEGAL_DEADLINE",
            "requires_counsel_confirmation": True, **estimates})
    return mutate_case(case_dir, "counter_notice_recorded", record)


def resolve_legal_task(case_dir: Path, task_id: str, reviewer: str, disposition: str) -> dict:
    if not reviewer.strip() or not disposition.strip():
        raise ValueError("Named reviewer and documented disposition required")
    def resolve(data):
        task = next((t for t in data["counter_notices"] if t["task_id"] == task_id), None)
        if task is None:
            raise KeyError(task_id)
        if task["status"] != "OPEN":
            raise ConflictError("Legal task already reviewed")
        task.update(status="REVIEWED", reviewer=reviewer, disposition=disposition, reviewed_at=utc_now())
        channel = _channel(data, task["channel_id"])
        channel["legal_review_epoch"] = channel.get("legal_review_epoch", 0) + 1
        if not open_legal_tasks(data, task["channel_id"]):
            pause = channel.pop("legal_pause", {})
            remaining = pause.get("remaining_seconds")
            if remaining is not None and channel["status"] in ACTIVE_SLA_CHANNEL_STATUSES:
                channel["next_action_due_at"] = _format_iso_utc(_parse_iso_utc(utc_now()) + timedelta(seconds=remaining))
            channel["history"].append({"event": "legal_pause_released", "reviewer": reviewer, "timestamp": utc_now()})
        if not any(t["status"] == "OPEN" for t in data["counter_notices"]):
            data["status"] = "WATCHLIST_RESURRECTION" if data.get("liveness_review", {}).get("decision") == "DOWN" else "ACTIVE_ENFORCEMENT"
    return mutate_case(case_dir, "legal_task_reviewed", resolve)


def review_liveness(case_dir: Path, decision: str, reviewer: str, source_ref: str,
                    evidence: list[dict], summary: str) -> dict:
    if decision not in ("DOWN", "ACTIVE"):
        raise ValueError("Liveness decision must be DOWN or ACTIVE")
    if not all(isinstance(x, str) and x.strip() for x in (reviewer, source_ref, summary)):
        raise ValueError("Reviewer, source reference and summary required")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("Liveness review requires sealed evidence references")
    def review(data):
        from recon_target import verify_capture
        covered = set()
        for ref in evidence:
            if not isinstance(ref, dict) or not isinstance(ref.get("capture_id"), str) or not isinstance(ref.get("filename"), str):
                raise ValueError("Invalid review evidence reference")
            manifest = verify_capture(case_dir, ref["capture_id"])
            capture = next(c for c in data["captures"] if c["capture_id"] == ref["capture_id"])
            entry = next((f for f in manifest["files"] if f["filename"] == ref["filename"]), None)
            if (capture["status"] not in ("CAPTURED", "USER_SUPPLIED", "PARTIAL") or not entry
                    or not entry["size_bytes"] or ref["filename"] in ("recon-report.json", "headers.json")):
                raise ValueError("Select substantive review evidence")
            covered.add(manifest["target_url"])
            if ref.get("observed_urls"):
                if capture["status"] != "USER_SUPPLIED" or not isinstance(ref["observed_urls"], list):
                    raise ValueError("Multi-URL observations require a user-supplied review document")
                for observed in ref["observed_urls"]:
                    covered.add(check_target(observed, case_profile(case_dir)))
        required = set(data["target_urls"]) | {"https://" + item["domain"] + "/" for item in data["linked_payment_cloak_domains"]}
        if decision == "DOWN" and not required.issubset(covered):
            raise ValueError("A down review must cover every registered target and linked URL")
        record = {"review_id": uuid.uuid4().hex, "decision": decision, "reviewer": reviewer.strip(),
                  "source_ref": source_ref.strip(), "summary": summary.strip(), "evidence": evidence,
                  "reviewed_at": utc_now(), "target_urls": list(data["target_urls"]),
                  "linked_domains": [x["domain"] for x in data["linked_payment_cloak_domains"]]}
        data.setdefault("liveness_reviews", []).append(record)
        data["liveness_review"] = record
        if data.get("resurrection_alert"):
            data.setdefault("resurrection_alert_history", []).append(data["resurrection_alert"])
        data.pop("resurrection_alert", None)
        data["liveness_state"] = "REVIEWED_DOWN" if decision == "DOWN" else "REVIEWED_ACTIVE"
        data["status"] = "WATCHLIST_RESURRECTION" if decision == "DOWN" else "ACTIVE_ENFORCEMENT"
    return mutate_case(case_dir, "liveness_reviewed", review)


def _main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH)
    sub = parser.add_subparsers(dest="cmd", required=True)
    create = sub.add_parser("create")
    create.add_argument("--slug", required=True)
    create.add_argument("--url", required=True)
    create.add_argument("--types", nargs="+", choices=INFRINGING_TYPES, required=True)
    for name in ("due", "summary"):
        p = sub.add_parser(name); p.add_argument("--slug", required=True)
    for name in ("add-channel", "update-channel", "escalate", "add-cloak", "counter-notice", "submit", "resolve-legal", "review-liveness"):
        p = sub.add_parser(name)
        p.add_argument("--slug", required=True)
        p.add_argument("--case-dir", type=Path, required=True)
        if name not in ("add-cloak", "resolve-legal", "review-liveness"):
            p.add_argument("--channel-id", required=True)
        if name == "add-channel":
            p.add_argument("--channel-class", choices=CHANNEL_CLASSES, required=True)
            p.add_argument("--category", required=True); p.add_argument("--provider", required=True); p.add_argument("--endpoint", required=True)
        elif name == "update-channel":
            p.add_argument("--status"); p.add_argument("--ticket-ref")
        elif name == "add-cloak":
            p.add_argument("--domain", required=True)
        elif name == "counter-notice":
            for field in ("received-at", "summary", "source-ref"):
                p.add_argument("--" + field, required=True)
            p.add_argument("--provider-received-at"); p.add_argument("--provider-timezone", default="UTC")
        elif name == "submit":
            for field in ("packet-id", "submission-ref", "sent-at"):
                p.add_argument("--" + field, required=True)
        elif name == "review-liveness":
            p.add_argument("--decision", choices=("DOWN", "ACTIVE"), required=True)
            p.add_argument("--reviewer", required=True); p.add_argument("--source-ref", required=True)
            p.add_argument("--summary", required=True); p.add_argument("--evidence-file", type=Path, required=True)
        elif name == "resolve-legal":
            for field in ("task-id", "reviewer", "disposition"):
                p.add_argument("--" + field, required=True)
    args = parser.parse_args(argv)
    brand_dir, profile = load_brand_profile(args.slug, args.registry)
    if hasattr(args, "case_dir"):
        assert_case_brand(args.case_dir, brand_dir)
    if args.cmd == "create":
        path, data = create_case(brand_dir, args.url, args.types)
        result = {"case_dir": str(path), "case": data}
    elif args.cmd == "due":
        result = {"items": scan_due_escalations(brand_dir)}
    elif args.cmd == "summary":
        result = {"cases": [load_case(c) for c in sorted((brand_dir / "cases").iterdir()) if c.is_dir()]}
    elif args.cmd == "add-channel":
        result = upsert_channel(args.case_dir, args.channel_id, args.channel_class, args.category, args.provider, args.endpoint)
    elif args.cmd == "update-channel":
        result = update_channel_fields(args.case_dir, args.channel_id, args.status, args.ticket_ref)
    elif args.cmd == "escalate":
        result = advance_escalation_tier(args.case_dir, args.channel_id)
    elif args.cmd == "add-cloak":
        result = add_linked_cloak_domain(args.case_dir, args.domain)
    elif args.cmd == "counter-notice":
        result = record_counter_notice(args.case_dir, args.channel_id, args.received_at, args.summary, args.provider_received_at, args.provider_timezone, args.source_ref)
    elif args.cmd == "review-liveness":
        refs = read_json(args.evidence_file).get("evidence")
        result = review_liveness(args.case_dir, args.decision, args.reviewer, args.source_ref, refs, args.summary)
    elif args.cmd == "resolve-legal":
        result = resolve_legal_task(args.case_dir, args.task_id, args.reviewer, args.disposition)
    else:
        result = confirm_submission(args.case_dir, args.channel_id, args.packet_id, args.submission_ref, args.sent_at)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return int(any(i.get("kind") == "CASE_ERROR" for i in result.get("items", [])))


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr); sys.exit(2)
