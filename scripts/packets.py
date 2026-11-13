"""Evidence-bound notice drafts, explicit human review, and hash-bound approval.

Approval is a local workflow record, not a digital signature or proof of authority.
There is no SMTP/Gmail/web-form submission in this module.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid

from brand_registry import DEFAULT_REGISTRY_PATH, check_target, load_brand_profile, normalize_hostname, sanitize_http_url, utc_now
from case_manager import _parse_iso_utc, assert_case_brand, case_profile, load_case
from recon_target import verify_capture
from storage import atomic_write_bytes, atomic_write_json, locked, read_json, safe_path

ROUTES = {
    "COPYRIGHT_NOTICE": {"COPYRIGHT"}, "TRADEMARK_NOTICE": {"TRADEMARK", "COUNTERFEIT"},
    "DESIGN_NOTICE": {"DESIGN"}, "ABUSE_REPORT": {"PHISHING"},
    "SAFETY_REFERRAL": {"PRODUCT_SAFETY"}, "REGULATORY_FILING": {"COPYRIGHT", "TRADEMARK", "COUNTERFEIT", "DESIGN", "PHISHING", "PRODUCT_SAFETY"},
    "DSA_NOTICE": {"COPYRIGHT", "TRADEMARK", "COUNTERFEIT", "DESIGN", "PHISHING", "PRODUCT_SAFETY"},
}
PLACEHOLDERS = re.compile(r"\{\{.*?\}\}|<SKILL_DIR>|<target_url>", re.S)
MAX_ATTACHMENTS_BYTES = 15 * 1024 * 1024


def _digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _text(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or PLACEHOLDERS.search(value):
        raise ValueError(f"Missing or unresolved {field}")
    return value.strip()


def _packet_path(case_dir: Path, packet_id: str) -> Path:
    if not re.fullmatch(r"PKT-[0-9a-f]{32}", packet_id):
        raise ValueError("Invalid packet id")
    return safe_path(case_dir) / "packets" / packet_id


def _select_signatory(profile: dict, request: dict) -> tuple[dict, str, str]:
    """Select shielded public_filing_agent when public/Lumen archiving is expected."""
    for flag in ("public_archive_expected", "use_public_filing_agent", "allow_primary_signatory_in_public_archive"):
        if flag in request and not isinstance(request[flag], bool):
            raise ValueError(f"{flag} must be a boolean")
    public_archive_expected = bool(request.get("public_archive_expected"))
    use_agent = bool(request.get("use_public_filing_agent"))
    allow_primary = bool(request.get("allow_primary_signatory_in_public_archive"))
    agent = profile.get("public_filing_agent")
    if use_agent or (public_archive_expected and agent):
        if not agent:
            raise ValueError("public_filing_agent requested but not configured in brand profile")
        return agent, agent["entity_address"], "PUBLIC_FILING_AGENT"
    if public_archive_expected and not allow_primary:
        raise ValueError(
            "Channel expects public/Lumen archiving: configure public_filing_agent in brand profile "
            "or explicitly set allow_primary_signatory_in_public_archive=true after privacy review"
        )
    return profile["authorized_signatory"], profile["entity_address"], "PRIMARY_SIGNATORY"


def _validate_request(case_dir: Path, request: dict) -> tuple[dict, dict, dict]:
    case = load_case(case_dir)
    profile = case_profile(case_dir)
    if not isinstance(request, dict) or PLACEHOLDERS.search(json.dumps(request)):
        raise ValueError("Invalid request or unresolved template placeholders")
    route = request.get("route")
    if route not in ROUTES:
        raise ValueError("Unknown legal route")
    channel = next((c for c in case["channels"] if c["channel_id"] == request.get("channel_id")), None)
    if channel is None or channel["status"] in ("RESOLVED", "REJECTED"):
        raise ValueError("Missing or closed channel")
    if channel["channel_class"] == "REGULATORY_FILING" and route not in ("REGULATORY_FILING", "SAFETY_REFERRAL"):
        raise ValueError("Regulatory channels require an informational filing route")
    for field in ("subject", "endpoint_source_url", "endpoint_verified_by", "endpoint_verified_at", "provider_role", "scope_reason", "authorization_fair_use_review", "rights_verified_by", "rights_verified_at"):
        _text(request.get(field), field)
    if "\r" in request["subject"] or "\n" in request["subject"]:
        raise ValueError("Header injection rejected")
    now = datetime.now(timezone.utc)
    for field in ("endpoint_verified_at", "rights_verified_at"):
        checked = _parse_iso_utc(request[field])
        if checked > now + timedelta(minutes=5) or now - checked > timedelta(days=30):
            raise ValueError(f"{field}: refresh verification within 30 days")
    source = sanitize_http_url(request["endpoint_source_url"])
    bad_hosts = [case["primary_domain"]] + [x["domain"] for x in case["linked_payment_cloak_domains"]]
    if not source.startswith("https://") or any(normalize_hostname(source) == h or normalize_hostname(source).endswith("." + h) for h in bad_hosts):
        raise ValueError("Endpoint provenance must be an independently verified HTTPS provider source")
    if request.get("jurisdiction") not in profile["target_markets"]:
        raise ValueError("Explicit supported case market required; GLOBAL is not a legal jurisdiction")
    if request["jurisdiction"] in ("GLOBAL", "CN_EXPORT") and route not in ("REGULATORY_FILING", "ABUSE_REPORT"):
        raise ValueError("Select an actual legal jurisdiction")
    if route == "DSA_NOTICE" and (request["jurisdiction"] != "EU" or request["provider_role"] != "hosting"):
        raise ValueError("DSA Article 16 route requires an EU scope assessment and hosting role")
    if route == "COPYRIGHT_NOTICE" and request["jurisdiction"] != "US":
        raise ValueError("This copyright template is US DMCA only; other jurisdictions need a reviewed filing")
    claims = request.get("claims")
    if not isinstance(claims, list) or not claims:
        raise ValueError("No evidence-backed claims")
    for claim in claims:
        if not isinstance(claim, dict) or claim.get("kind") not in ROUTES[route]:
            raise ValueError("Claim does not match selected route")
        target = check_target(_text(claim.get("target_url"), "target_url"), profile)
        if target not in case["target_urls"]:
            raise ValueError("Claim target is not in this case")
        _text(claim.get("statement"), "claim statement")
        _text(claim.get("legal_basis"), "specific legal basis")
        _text(claim.get("comparison_or_observed_facts"), "comparison or observed facts")
        refs = claim.get("evidence")
        if not isinstance(refs, list) or not refs:
            raise ValueError("Each claim needs evidence file references")
        for ref in refs:
            manifest = verify_capture(case_dir, ref["capture_id"])
            capture = next(c for c in case["captures"] if c["capture_id"] == ref["capture_id"])
            if capture["status"] not in ("CAPTURED", "USER_SUPPLIED") or manifest["target_url"] != target:
                raise ValueError("Failed/partial or different-target capture cannot support this claim")
            entry = next((f for f in manifest["files"] if f["filename"] == ref["filename"]), None)
            if not entry or not entry["size_bytes"] or ref["filename"] in ("recon-report.json", "headers.json"):
                raise ValueError("Select substantive, nonempty evidence, not capture metadata")
        kind = claim["kind"]
        sections = {"COPYRIGHT": "copyright_originals", "TRADEMARK": "trademarks", "COUNTERFEIT": "trademarks", "DESIGN": "patents_and_designs"}
        if kind in sections:
            index = claim.get("right_index")
            rights = profile.get(sections[kind], [])
            if type(index) is not int or not 0 <= index < len(rights):
                raise ValueError("Claim needs a valid right_index")
            right = rights[index]
            if kind != "COPYRIGHT":
                if right.get("jurisdiction") != request["jurisdiction"]:
                    raise ValueError("Right territory differs from selected jurisdiction")
                if right.get("status", "registered") == "pending":
                    raise ValueError("Pending registration cannot support a registered-right notice")
                if right.get("expiry_date") and date.fromisoformat(right["expiry_date"]) < date.today():
                    raise ValueError("Expired right requires legal review")
                if kind in ("COUNTERFEIT", "DESIGN") and right.get("status", "registered") != "registered":
                    raise ValueError("This route requires a verified registered right")
                if right.get("status", "registered") == "registered" and not right.get("cert_file_path"):
                    raise ValueError("Registered-right notice requires a certificate attachment")
        if kind == "PRODUCT_SAFETY":
            _text(claim.get("specific_requirement_and_defect"), "specific product requirement and observed defect")
    _select_signatory(profile, request)
    return case, profile, channel


def _prepare_packet(case_dir: Path, request: dict) -> dict:
    case, profile, channel = _validate_request(case_dir, request)
    packet_id = "PKT-" + uuid.uuid4().hex
    directory = _packet_path(case_dir, packet_id)
    directory.mkdir(mode=0o700, exist_ok=False)
    attachments = []
    total = 0
    seen = set()
    sources = []
    for claim in request["claims"]:
        sources.extend(safe_path(case_dir) / "evidence" / ref["capture_id"] / ref["filename"] for ref in claim["evidence"])
        section = {"COPYRIGHT": "copyright_originals", "TRADEMARK": "trademarks", "COUNTERFEIT": "trademarks", "DESIGN": "patents_and_designs"}.get(claim["kind"])
        if section:
            right = profile[section][claim["right_index"]]
            sources.extend(Path(right[k]) for k in ("cert_file_path", "drawings_file_path") if right.get(k))
    for source in sources:
        source = safe_path(source)
        if str(source) in seen:
            continue
        seen.add(str(source))
        if not source.is_file() or source.stat().st_size + total > MAX_ATTACHMENTS_BYTES:
            raise ValueError("Attachments must be regular files totaling at most 15 MiB")
        content = source.read_bytes(); total += len(content)
        if total > MAX_ATTACHMENTS_BYTES:
            raise ValueError("Attachment grew beyond budget")
        name = f"{len(attachments):03d}-" + source.name
        atomic_write_bytes(directory / name, content)
        attachments.append({"filename": name, "sha256": _digest(content), "size_bytes": len(content)})
    lines = ["Dear Review Team,", "", f"{profile['legal_entity_name_en']} requests review of the following alleged issues.",
             f"Selected route: {request['route']}; scope: {request['scope_reason']}", ""]
    for claim in request["claims"]:
        lines.extend([f"URL: {claim['target_url']}", f"Claim: {claim['kind']}", f"Allegation: {claim['statement']}",
                      f"Observed comparison/facts: {claim['comparison_or_observed_facts']}", f"Basis for review: {claim['legal_basis']}"])
        section = {"COPYRIGHT": "copyright_originals", "TRADEMARK": "trademarks", "COUNTERFEIT": "trademarks", "DESIGN": "patents_and_designs"}.get(claim["kind"])
        if section:
            right = {k: v for k, v in profile[section][claim["right_index"]].items() if not k.endswith("file_path")}
            lines.append("Rights record: " + json.dumps(right, ensure_ascii=False))
        if claim["kind"] == "PRODUCT_SAFETY":
            lines.append("Specific requirement and observed defect: " + claim["specific_requirement_and_defect"])
        lines.append("")
    lines.extend(["Please assess the evidence and take appropriate, proportionate action under the applicable policy or law.",
                  "Please acknowledge receipt and provide your decision and any available review route."])
    if request["route"] == "COPYRIGHT_NOTICE":
        lines.extend(["I have a good faith belief that use of the material in the manner complained of is not authorized by the copyright owner, its agent, or the law.",
                      "The information in this notification is accurate, and under penalty of perjury I am authorized to act on behalf of the owner of an exclusive right that is allegedly infringed."])
    elif request["route"] == "DSA_NOTICE":
        lines.append("I confirm my bona fide belief that the information and allegations in this notice are accurate and complete.")
    else:
        lines.append("The allegations are submitted in good faith for review; no outcome or provider liability is assumed.")
    signer, signer_address, signatory_mode = _select_signatory(profile, request)
    sig_lines = ["", "/s/ " + signer["name"], signer["title"]]
    if signatory_mode == "PUBLIC_FILING_AGENT":
        sig_lines.append(f"Authorized Filing Agent for {profile['legal_entity_name_en']}")
    sig_lines.extend([signer_address, signer["legal_email"], signer.get("phone", "")])
    lines.extend(sig_lines)
    body = "\n".join(lines) + "\n"
    if request["route"] == "COPYRIGHT_NOTICE" and not signer.get("phone", "").strip():
        raise ValueError("Complete contact information, including telephone, required for this DMCA packet")
    atomic_write_bytes(directory / "notice.txt", body.encode("utf-8"))
    packet = {"schema_version": 2, "packet_id": packet_id, "case_id": case["case_id"], "brand_id": profile["brand_id"],
        "profile_sha256": _digest((safe_path(case_dir).parent.parent / "profile.json").read_bytes()),
        "channel_id": channel["channel_id"], "endpoint": channel["target_endpoint"], "tier": channel.get("pending_tier", 1),
        "from_addr": signer["legal_email"], "signatory_mode": signatory_mode,
        "public_archive_expected": bool(request.get("public_archive_expected")),
        "disclosure_advisory": "Notices may be forwarded to the merchant and indexed in public archives (e.g., Lumen Database); redact personal PII before approval.",
        "subject": request["subject"], "request": request,
        "body_sha256": _digest(body.encode("utf-8")), "attachments": attachments, "created_at": utc_now()}
    atomic_write_json(directory / "packet.json", packet)
    return {"packet_id": packet_id, "status": "DRAFT_REQUIRES_HUMAN_REVIEW", "packet_dir": str(directory), "packet_sha256": _digest((directory / "packet.json").read_bytes())}


def _verify_packet(case_dir: Path, packet_id: str) -> dict:
    directory = _packet_path(case_dir, packet_id)
    packet = read_json(directory / "packet.json")
    if packet.get("packet_id") != packet_id:
        raise ValueError("Packet identity mismatch")
    case, profile, channel = _validate_request(case_dir, packet["request"])
    if packet["case_id"] != case["case_id"] or packet["brand_id"] != profile["brand_id"] or packet["endpoint"] != channel["target_endpoint"]:
        raise ValueError("Packet context changed")
    if packet["profile_sha256"] != _digest((safe_path(case_dir).parent.parent / "profile.json").read_bytes()):
        raise ValueError("Brand profile changed; regenerate and reapprove packet")
    if _digest(safe_path(directory / "notice.txt").read_bytes()) != packet["body_sha256"]:
        raise ValueError("Notice body changed after preparation")
    for att in packet["attachments"]:
        if Path(att["filename"]).name != att["filename"]:
            raise ValueError("Invalid attachment path")
        content = safe_path(directory / att["filename"]).read_bytes()
        if _digest(content) != att["sha256"] or len(content) != att["size_bytes"]:
            raise ValueError("Packet attachment changed")
    return packet


def _approve_packet(case_dir: Path, packet_id: str, reviewer: str, reviewed_digest: str, confirmed=False) -> dict:
    if not confirmed or not reviewer.strip():
        raise ValueError("Explicit human authorization and reviewer identity required")
    directory = _packet_path(case_dir, packet_id)
    with locked(directory / ".approval.lock"):
        _verify_packet(case_dir, packet_id)
        digest = _digest((directory / "packet.json").read_bytes())
        if reviewed_digest != digest:
            raise ValueError("Displayed packet digest no longer matches")
        approval = {"packet_sha256": digest, "reviewer": reviewer, "approved_at": utc_now(),
                    "attestation": "Human reviewed authority, fair use/resale, facts, jurisdiction, recipients, body and exact attachments; disclosure risk accepted"}
        atomic_write_json(directory / "approval.json", approval)
    return approval


def _verify_approved_packet(case_dir: Path, packet_id: str) -> dict:
    directory = _packet_path(case_dir, packet_id)
    packet = _verify_packet(case_dir, packet_id)
    approval = read_json(directory / "approval.json")
    if not approval.get("reviewer") or approval["packet_sha256"] != _digest((directory / "packet.json").read_bytes()):
        raise ValueError("Missing or stale approval")
    if datetime.now(timezone.utc) - _parse_iso_utc(approval["approved_at"]) > timedelta(days=7):
        raise ValueError("Approval older than seven days; review again")
    packet["approval"] = approval
    return packet



def prepare_packet(case_dir: Path, request: dict) -> dict:
    case_dir = safe_path(case_dir)
    with locked(case_dir.parent.parent / ".brand.lock"), locked(case_dir / ".case.lock"):
        return _prepare_packet(case_dir, request)


def approve_packet(case_dir: Path, packet_id: str, reviewer: str, reviewed_digest: str, confirmed=False) -> dict:
    case_dir = safe_path(case_dir)
    with locked(case_dir.parent.parent / ".brand.lock"), locked(case_dir / ".case.lock"):
        return _approve_packet(case_dir, packet_id, reviewer, reviewed_digest, confirmed)


def verify_approved_packet(case_dir: Path, packet_id: str) -> dict:
    case_dir = safe_path(case_dir)
    with locked(case_dir.parent.parent / ".brand.lock"), locked(case_dir / ".case.lock"):
        return _verify_approved_packet(case_dir, packet_id)


def _main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH)
    parser.add_argument("--slug", required=True); parser.add_argument("--case-dir", type=Path, required=True)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare"); p.add_argument("--request-file", type=Path, required=True)
    p = sub.add_parser("approve")
    p.add_argument("--packet-id", required=True); p.add_argument("--reviewer", required=True); p.add_argument("--reviewed-digest", required=True)
    p.add_argument("--confirm-human-review", action="store_true")
    p = sub.add_parser("verify"); p.add_argument("--packet-id", required=True)
    args = parser.parse_args(argv)
    brand_dir, _ = load_brand_profile(args.slug, args.registry)
    assert_case_brand(args.case_dir, brand_dir)
    if args.cmd == "prepare":
        result = prepare_packet(args.case_dir, read_json(args.request_file))
    elif args.cmd == "approve":
        result = approve_packet(args.case_dir, args.packet_id, args.reviewer, args.reviewed_digest, args.confirm_human_review)
    else:
        result = verify_approved_packet(args.case_dir, args.packet_id)
    print(json.dumps(result, ensure_ascii=False, indent=2)); return 0


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr); sys.exit(2)
