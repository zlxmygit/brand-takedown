from __future__ import annotations

import argparse
import json
import mimetypes
import sys
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path


def create_eml_file(
    output_path: Path,
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    markdown_or_text_body: str,
    attachment_paths: list[Path],
    cc_addrs: list[str] | None = None,
    reply_to: str | None = None,
) -> Path:
    if not from_addr.strip():
        raise ValueError("from_addr is required")
    if not to_addrs:
        raise ValueError("at least one recipient in to_addrs is required")

    msg = EmailMessage()
    msg["From"] = from_addr.strip()
    msg["To"] = ", ".join(addr.strip() for addr in to_addrs if addr.strip())
    if cc_addrs:
        clean_cc = [addr.strip() for addr in cc_addrs if addr.strip()]
        if clean_cc:
            msg["Cc"] = ", ".join(clean_cc)
    if reply_to and reply_to.strip():
        msg["Reply-To"] = reply_to.strip()

    msg["Subject"] = subject.strip()
    msg["Date"] = formatdate(localtime=True)
    domain_part = from_addr.partition("@")[2].strip() or "brand-protection.local"
    msg["Message-ID"] = make_msgid(domain=domain_part)
    msg.set_content(markdown_or_text_body, subtype="plain", charset="utf-8")

    for att in attachment_paths:
        resolved = att.expanduser().resolve()
        if not resolved.is_file():
            raise FileNotFoundError(f"Attachment not found: {resolved}")
        guessed_type, _ = mimetypes.guess_type(resolved.name)
        if guessed_type and "/" in guessed_type:
            maintype, subtype = guessed_type.split("/", 1)
        else:
            maintype, subtype = "application", "octet-stream"
        msg.add_attachment(
            resolved.read_bytes(),
            maintype=maintype,
            subtype=subtype,
            filename=resolved.name,
        )

    out = output_path.expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(bytes(msg))
    return out


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build standard RFC 5322 .eml file with corporate From header & UTF-8 attachments.")
    parser.add_argument("--out", type=Path, required=True, help="Output .eml path")
    parser.add_argument("--from-addr", required=True, help="Official brand legal email address")
    parser.add_argument("--to", nargs="+", required=True, help="Recipient email address(es)")
    parser.add_argument("--cc", nargs="*", default=[], help="Optional CC address(es)")
    parser.add_argument("--reply-to", default=None, help="Optional Reply-To address")
    parser.add_argument("--subject", required=True, help="Email subject")
    parser.add_argument("--body-file", type=Path, required=True, help="UTF-8 plain text / markdown file for email body")
    parser.add_argument("--attachments", type=Path, nargs="*", default=[], help="Optional attachment file paths")

    args = parser.parse_args(argv)
    body_text = args.body_file.read_text(encoding="utf-8")
    saved = create_eml_file(
        output_path=args.out,
        from_addr=args.from_addr,
        to_addrs=args.to,
        subject=args.subject,
        markdown_or_text_body=body_text,
        attachment_paths=args.attachments,
        cc_addrs=args.cc,
        reply_to=args.reply_to,
    )
    print(
        json.dumps(
            {
                "eml_path": str(saved),
                "size_bytes": saved.stat().st_size,
                "attachment_count": len(args.attachments),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(_main())
