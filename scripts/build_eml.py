"""Build an unsent SMTP-format message from a reviewed packet; never send mail."""
from __future__ import annotations

import argparse
from email.headerregistry import Address
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate, make_msgid
import json
import mimetypes
from pathlib import Path
import re
import sys

from brand_registry import DEFAULT_REGISTRY_PATH, is_allowlisted_url, load_brand_profile
from case_manager import assert_case_brand, case_profile
from packets import MAX_ATTACHMENTS_BYTES, PLACEHOLDERS, _packet_path, verify_approved_packet
from storage import atomic_write_bytes, locked, safe_path


def validate_address(value: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not re.fullmatch(r"[^\s@<>;,]+@[^\s@<>;,]+\.[^\s@<>;,]+", value):
        raise ValueError("A single plain email address is required")
    address = Address(addr_spec=value)
    if not address.username or not address.domain:
        raise ValueError("Invalid email address")
    value.encode("ascii")
    return value


def create_eml_file(output_path: Path, from_addr: str, to_addrs: list[str], subject: str,
                    markdown_or_text_body: str, attachment_paths: list[Path], cc_addrs=None, reply_to=None) -> Path:
    # Public helper produces drafts only; the CLI additionally requires packet approval.
    sender = validate_address(from_addr)
    if not to_addrs:
        raise ValueError("At least one recipient is required")
    recipients = [validate_address(addr) for addr in to_addrs]
    if not subject.strip() or "\r" in subject or "\n" in subject or PLACEHOLDERS.search(subject + markdown_or_text_body):
        raise ValueError("Invalid subject or unresolved placeholders")
    if not markdown_or_text_body.strip():
        raise ValueError("Empty message body")
    message = EmailMessage(policy=SMTP)
    message["From"] = sender; message["To"] = ", ".join(recipients)
    if cc_addrs:
        message["Cc"] = ", ".join(validate_address(addr) for addr in cc_addrs)
    if reply_to:
        message["Reply-To"] = validate_address(reply_to)
    message["Subject"] = subject; message["Date"] = formatdate(localtime=False)
    message["Message-ID"] = make_msgid(domain=sender.split("@", 1)[1])
    message["X-Unsent"] = "1"
    message["X-Brand-Takedown-Mode"] = "draft-only"
    message.set_content(markdown_or_text_body)
    total = 0
    for path in attachment_paths:
        path = safe_path(path)
        if not path.is_file() or path.stat().st_size + total > MAX_ATTACHMENTS_BYTES:
            raise ValueError("Invalid attachment or total size exceeds 15 MiB")
        content = path.read_bytes(); total += len(content)
        if total > MAX_ATTACHMENTS_BYTES:
            raise ValueError("Attachment grew beyond budget")
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        main, sub = mime.split("/", 1)
        message.add_attachment(content, maintype=main, subtype=sub, filename=path.name)
    output_path = safe_path(output_path)
    if output_path in [safe_path(p) for p in attachment_paths]:
        raise ValueError("Output must not overwrite an input attachment")
    atomic_write_bytes(output_path, message.as_bytes(policy=SMTP))
    return output_path


def _build_approved_eml(case_dir: Path, packet_id: str, output_path: Path) -> Path:
    packet = verify_approved_packet(case_dir, packet_id)
    profile = case_profile(case_dir)
    sender = validate_address(packet["from_addr"])
    mode = packet.get("signatory_mode")
    configured = profile.get("public_filing_agent") if mode == "PUBLIC_FILING_AGENT" else profile["authorized_signatory"]
    if mode not in ("PUBLIC_FILING_AGENT", "PRIMARY_SIGNATORY") or not configured or sender != validate_address(configured["legal_email"]):
        raise ValueError("Sender differs from the approved configured signatory")
    if mode == "PRIMARY_SIGNATORY" and not is_allowlisted_url(sender.split("@", 1)[1], profile["official_domains"]):
        raise ValueError("Sender is not on an official brand domain")
    endpoint = validate_address(packet["endpoint"])
    directory = _packet_path(case_dir, packet_id)
    if safe_path(output_path).parent != directory or output_path.name != "notice.eml":
        raise ValueError("Output must be this packet's notice.eml")
    return create_eml_file(output_path, sender, [endpoint], packet["subject"],
        (directory / "notice.txt").read_text(encoding="utf-8"), [directory / a["filename"] for a in packet["attachments"]])


def build_approved_eml(case_dir: Path, packet_id: str, output_path: Path) -> Path:
    case_dir = safe_path(case_dir)
    with locked(case_dir.parent.parent / ".brand.lock"), locked(case_dir / ".case.lock"):
        return _build_approved_eml(case_dir, packet_id, output_path)


def _main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH)
    parser.add_argument("--slug", required=True); parser.add_argument("--case-dir", type=Path, required=True)
    parser.add_argument("--packet-id", required=True)
    args = parser.parse_args(argv)
    directory, _ = load_brand_profile(args.slug, args.registry)
    assert_case_brand(args.case_dir, directory)
    out = _packet_path(args.case_dir, args.packet_id) / "notice.eml"
    print(json.dumps({"eml_path": str(build_approved_eml(args.case_dir, args.packet_id, out)), "sent": False}))
    return 0


if __name__ == "__main__":
    from runtime_support import configure_cli
    configure_cli()
    try:
        sys.exit(_main())
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr); sys.exit(2)
