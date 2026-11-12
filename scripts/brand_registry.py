from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_REGISTRY_PATH = Path.home() / ".gemini" / "brand-protection" / "registry.json"
VALID_MARKETS = {"US", "CA", "EU", "UK", "AU", "CN_EXPORT", "GLOBAL"}
SLUG_PATTERN = re.compile(r"^[a-z0-9-]+$")
LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
CONTROL_OR_SPACE_RE = re.compile(r"[\s\x00-\x1f\x7f]")


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp_path, path)


def _validate_rfc1123_fqdn(candidate: str) -> str:
    host = candidate.strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host or len(host) > 253 or "." not in host or "\\" in host:
        return ""
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    labels = ascii_host.split(".")
    if len(labels) < 2:
        return ""
    for label in labels:
        if not LABEL_PATTERN.match(label):
            return ""
    if labels[-1].isdigit():
        return ""
    return ascii_host


def normalize_hostname(url_or_domain: str) -> str:
    raw = (url_or_domain or "").strip()
    if not raw or raw.startswith("-") or CONTROL_OR_SPACE_RE.search(raw) or "\\" in raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in ("http", "https"):
            return ""
        host = parsed.hostname or ""
    else:
        if ":" in raw.split("/")[0] and not raw.split("/")[0].rpartition(":")[2].isdigit():
            return ""
        parsed = urlparse("https://" + raw)
        host = parsed.hostname or ""
    return _validate_rfc1123_fqdn(host)


def sanitize_http_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw or raw.startswith("-"):
        raise ValueError(f"Empty or flag-like URL rejected: {url!r}")
    if CONTROL_OR_SPACE_RE.search(raw) or "\\" in raw:
        raise ValueError(f"Malformed URL containing whitespace, control chars, or backslashes rejected: {url!r}")
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Only http/https URLs are allowed; got scheme {parsed.scheme!r} in {url!r}")
    if parsed.username is not None or parsed.password is not None or "@" in (parsed.netloc or ""):
        raise ValueError(f"URLs containing userinfo '@' are rejected for anti-spoofing safety: {url!r}")
    fqdn = _validate_rfc1123_fqdn(parsed.hostname or "")
    if not fqdn:
        raise ValueError(f"Invalid RFC 1123 FQDN hostname in URL: {url!r}")
    return raw


def _extract_defensive_host_candidates(url_or_domain: str) -> list[str]:
    raw = (url_or_domain or "").strip()
    if not raw:
        return []
    repaired = raw.replace("\\", "/")
    repaired = re.sub(r"^(https?):(?!//)/*", r"\1://", repaired, flags=re.IGNORECASE)
    candidates: list[str] = []

    strict = normalize_hostname(repaired)
    if strict:
        candidates.append(strict)

    parsed = urlparse(repaired if "://" in repaired else "https://" + repaired)
    netloc = parsed.netloc or ""
    for part in netloc.split("@"):
        host_only = part.split(":")[0]
        fqdn = _validate_rfc1123_fqdn(host_only)
        if fqdn and fqdn not in candidates:
            candidates.append(fqdn)
    return candidates


def is_allowlisted_url(url_or_domain: str, allowlist_domains: list[str]) -> bool:
    candidates = _extract_defensive_host_candidates(url_or_domain)
    if not candidates:
        return False
    normalized_allow = [_validate_rfc1123_fqdn(str(item)) for item in (allowlist_domains or [])]
    valid_allow = [a for a in normalized_allow if a]
    for host in candidates:
        for allowed in valid_allow:
            if host == allowed or host.endswith("." + allowed):
                return True
    return False


def validate_profile(profile: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(profile, dict):
        return ["profile must be a JSON object"]

    slug = str(profile.get("brand_slug", "")).strip()
    if not slug or not SLUG_PATTERN.match(slug):
        errors.append("brand_slug is required and must match ^[a-z0-9-]+$")

    for key in ("brand_name", "legal_entity_name_en", "entity_address"):
        if not str(profile.get(key, "")).strip():
            errors.append(f"{key} is required and cannot be empty")

    signatory = profile.get("authorized_signatory")
    if not isinstance(signatory, dict):
        errors.append("authorized_signatory must be an object")
    else:
        for field in ("name", "title", "legal_email"):
            if not str(signatory.get(field, "")).strip():
                errors.append(f"authorized_signatory.{field} is required")

    official_domains = profile.get("official_domains")
    if not isinstance(official_domains, list) or len(official_domains) == 0:
        errors.append("official_domains must be a non-empty list of domains")
    else:
        for dom in official_domains:
            if not normalize_hostname(str(dom)):
                errors.append(f"invalid domain in official_domains: {dom!r}")

    allowlist_domains = profile.get("allowlist_domains", [])
    if not isinstance(allowlist_domains, list):
        errors.append("allowlist_domains must be a list of domain strings")
    else:
        for dom in allowlist_domains:
            if not normalize_hostname(str(dom)):
                errors.append(f"invalid domain in allowlist_domains: {dom!r}")

    markets = profile.get("target_markets")
    if not isinstance(markets, list) or len(markets) == 0:
        errors.append("target_markets must be a non-empty list")
    else:
        for market in markets:
            if market not in VALID_MARKETS:
                errors.append(f"unsupported target market {market!r}; valid={sorted(VALID_MARKETS)}")

    section_required_fields = {
        "trademarks": ("jurisdiction", "mark_text", "reg_number", "status"),
        "patents_and_designs": ("jurisdiction", "type", "reg_number"),
        "copyright_originals": ("asset_name", "official_source_url"),
    }
    for section, req_fields in section_required_fields.items():
        entries = profile.get(section, [])
        if entries is None:
            continue
        if not isinstance(entries, list):
            errors.append(f"{section} must be a list")
            continue
        for idx, item in enumerate(entries):
            if not isinstance(item, dict):
                errors.append(f"{section}[{idx}] must be an object")
                continue
            for req in req_fields:
                if not str(item.get(req, "")).strip():
                    errors.append(f"{section}[{idx}].{req} is required")
            for cert_key in ("cert_file_path", "drawings_file_path"):
                cert_val = str(item.get(cert_key, "")).strip()
                if cert_val and not Path(cert_val).exists():
                    errors.append(f"{section}[{idx}].{cert_key} does not exist: {cert_val}")

    return errors


def register_brand(
    brand_slug: str,
    data_dir: Path,
    profile: dict,
    registry_path: Path = DEFAULT_REGISTRY_PATH,
) -> Path:
    normalized_profile = dict(profile)
    normalized_profile["brand_slug"] = brand_slug.strip().lower()

    raw_official = normalized_profile.get("official_domains")
    raw_allow = normalized_profile.get("allowlist_domains", [])
    if not isinstance(raw_official, list) or not isinstance(raw_allow, list):
        errors = validate_profile(normalized_profile)
        raise ValueError("Invalid brand profile:\n- " + "\n- ".join(errors))

    official = [normalize_hostname(str(d)) for d in raw_official if normalize_hostname(str(d))]
    existing_allow = [normalize_hostname(str(d)) for d in raw_allow if normalize_hostname(str(d))]
    if len(official) != len(raw_official) or len(existing_allow) != len(raw_allow):
        errors = validate_profile(normalized_profile)
        raise ValueError("Invalid brand profile:\n- " + "\n- ".join(errors or ["malformed domain entry"]))

    merged_allow: list[str] = []
    for dom in official + existing_allow:
        if dom not in merged_allow:
            merged_allow.append(dom)
    normalized_profile["official_domains"] = official
    normalized_profile["allowlist_domains"] = merged_allow

    errors = validate_profile(normalized_profile)
    if errors:
        raise ValueError("Invalid brand profile:\n- " + "\n- ".join(errors))

    resolved_dir = data_dir.expanduser().resolve()
    (resolved_dir / "cases").mkdir(parents=True, exist_ok=True)
    (resolved_dir / "certificates").mkdir(parents=True, exist_ok=True)

    profile_path = resolved_dir / "profile.json"
    _atomic_write_json(profile_path, normalized_profile)

    registry_data: dict = {"brands": {}}
    if registry_path.exists():
        try:
            loaded = json.loads(registry_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("brands"), dict):
                registry_data = loaded
        except json.JSONDecodeError:
            registry_data = {"brands": {}}

    registry_data["brands"][normalized_profile["brand_slug"]] = {
        "brand_name": normalized_profile["brand_name"],
        "data_dir": str(resolved_dir),
        "profile_path": str(profile_path),
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    _atomic_write_json(registry_path, registry_data)
    return profile_path


def load_brand_profile(
    brand_slug: str,
    registry_path: Path = DEFAULT_REGISTRY_PATH,
) -> tuple[Path, dict]:
    if not registry_path.exists():
        raise FileNotFoundError(f"Brand registry not found at {registry_path}")
    registry_data = json.loads(registry_path.read_text(encoding="utf-8"))
    entry = registry_data.get("brands", {}).get(brand_slug.strip().lower())
    if not entry:
        raise KeyError(f"Brand {brand_slug!r} is not registered in {registry_path}")
    data_dir = Path(entry["data_dir"]).resolve()
    profile_path = data_dir / "profile.json"
    if not profile_path.exists():
        raise FileNotFoundError(f"Profile missing at {profile_path}")
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    return data_dir, profile


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage multi-brand profiles and allowlist checks.")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH, help="Path to global registry.json")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Register or update a brand profile from a JSON file")
    p_init.add_argument("--slug", required=True, help="Brand slug")
    p_init.add_argument("--data-dir", type=Path, required=True, help="Directory to store brand cases and profile.json")
    p_init.add_argument("--profile-file", type=Path, required=True, help="Input JSON file matching profile.schema.json")

    p_val = sub.add_parser("validate", help="Validate a profile.json file")
    p_val.add_argument("--profile-file", type=Path, required=True)

    sub.add_parser("list", help="List all registered brands")

    p_allow = sub.add_parser("check-allowlist", help="Exit 0 with JSON status showing whether URL hits allowlist")
    p_allow.add_argument("--slug", required=True)
    p_allow.add_argument("--url", required=True)

    args = parser.parse_args(argv)

    if args.cmd == "validate":
        data = json.loads(args.profile_file.read_text(encoding="utf-8"))
        errs = validate_profile(data)
        if errs:
            print(json.dumps({"valid": False, "errors": errs}, ensure_ascii=False, indent=2))
            return 1
        print(json.dumps({"valid": True, "errors": []}, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "init":
        data = json.loads(args.profile_file.read_text(encoding="utf-8"))
        saved = register_brand(args.slug, args.data_dir, data, registry_path=args.registry)
        print(json.dumps({"status": "registered", "profile_path": str(saved)}, ensure_ascii=False, indent=2))
        return 0

    if args.cmd == "list":
        if not args.registry.exists():
            print(json.dumps({"brands": {}}, ensure_ascii=False, indent=2))
            return 0
        print(args.registry.read_text(encoding="utf-8"))
        return 0

    if args.cmd == "check-allowlist":
        _, prof = load_brand_profile(args.slug, registry_path=args.registry)
        hit = is_allowlisted_url(args.url, prof.get("allowlist_domains", []))
        print(
            json.dumps(
                {
                    "url": args.url,
                    "normalized_host": normalize_hostname(args.url),
                    "allowlisted": hit,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(_main())
