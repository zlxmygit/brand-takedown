"""Validated brand identity and shared URL policy. Standard library only."""
from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit, urlunsplit
import uuid

from storage import ConflictError, atomic_write_json, locked, private_dir, read_json, safe_path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY_PATH = Path(os.environ.get("BRAND_TAKEDOWN_REGISTRY", str(Path.home() / ".gemini/brand-protection/registry.json")))
SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
CONTROL_OR_SPACE_RE = re.compile(r"[\s\x00-\x1f\x7f]")
VALID_MARKETS = {"US", "CA", "EU", "UK", "AU", "CN_EXPORT", "GLOBAL"}
COMMON_SECOND_LEVEL_PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "com.au", "net.au", "org.au",
    "com.cn", "net.cn", "org.cn", "com.br", "com.hk", "co.jp",
}
_atomic_write_json = atomic_write_json


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _validate_rfc1123_fqdn(candidate: str) -> str:
    if not isinstance(candidate, str) or CONTROL_OR_SPACE_RE.search(candidate):
        return ""
    try:
        host = candidate.lower().rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or labels[-1].isdigit():
        return ""
    return host if all(LABEL_PATTERN.fullmatch(label) for label in labels) else ""


def normalize_hostname(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("-") or CONTROL_OR_SPACE_RE.search(value) or "\\" in value:
        return ""
    try:
        parsed = urlsplit(value if "://" in value else "https://" + value)
        if parsed.scheme.lower() not in ("http", "https") or parsed.username is not None or parsed.password is not None:
            return ""
        _ = parsed.port
        return _validate_rfc1123_fqdn(parsed.hostname or "")
    except ValueError:
        return ""


def sanitize_http_url(url: str) -> str:
    if not isinstance(url, str) or not url or CONTROL_OR_SPACE_RE.search(url) or "\\" in url:
        raise ValueError("Malformed URL")
    try:
        parsed = urlsplit(url)
        host = normalize_hostname(url)
        if not host or parsed.scheme.lower() not in ("http", "https") or "://" not in url:
            raise ValueError("Only HTTP(S) URLs with a valid domain are supported")
        port = parsed.port
        if port is not None and port != (443 if parsed.scheme.lower() == "https" else 80):
            raise ValueError("Nonstandard ports are not supported")
        if parsed.fragment:
            raise ValueError("Fragments must be removed explicitly")
        if any(ord(ch) > 127 for ch in parsed.path + parsed.query):
            raise ValueError("Percent-encode non-ASCII paths and queries")
        return urlunsplit((parsed.scheme.lower(), host, parsed.path or "/", parsed.query, ""))
    except (ValueError, UnicodeError) as exc:
        raise ValueError(f"Unsafe URL: {url!r}") from exc


def is_allowlisted_url(value: str, allowlist_domains: list[str]) -> bool:
    # Conservative pre-validation check also recognizes misleading userinfo/backslashes.
    raw = str(value or "").replace("\\", "/")
    raw = re.sub(r"^(https?):(?!//)/*", r"\1://", raw, flags=re.I)
    candidates = {normalize_hostname(raw)}
    try:
        netloc = urlsplit(raw if "://" in raw else "https://" + raw).netloc
        candidates.update(_validate_rfc1123_fqdn(p.split(":")[0]) for p in netloc.split("@"))
    except ValueError:
        pass
    allowed = [_validate_rfc1123_fqdn(d) for d in allowlist_domains]
    return any(h and a and (h == a or h.endswith("." + a)) for h in candidates for a in allowed)


def profile_allowlist(profile: dict) -> list[str]:
    return sorted(set(profile["official_domains"] + profile.get("allowlist_domains", [])))


def check_target(url: str, profile: dict) -> str:
    if is_allowlisted_url(url, profile_allowlist(profile)):
        raise ValueError("SAFETY ABORT: target is an official or authorized domain")
    return sanitize_http_url(url)


def _schema_errors(value, schema: dict, path: str = "profile") -> list[str]:
    """Validate the closed subset used by our checked-in schema (not a general JSON Schema engine)."""
    errors = []
    types = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool}
    expected = schema.get("type")
    if expected and (not isinstance(value, types[expected]) or expected == "integer" and isinstance(value, bool)):
        return [f"{path}: expected {expected}"]
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: unsupported value")
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}.{key}: required")
        for key, item in value.items():
            if key in properties:
                errors.extend(_schema_errors(item, properties[key], f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}.{key}: unknown field")
    elif isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: too few items")
        if schema.get("uniqueItems") and len({json.dumps(v, sort_keys=True) for v in value}) != len(value):
            errors.append(f"{path}: duplicate items")
        for index, item in enumerate(value):
            errors.extend(_schema_errors(item, schema.get("items", {}), f"{path}[{index}]"))
    elif isinstance(value, int) and not isinstance(value, bool):
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            errors.append(f"{path}: outside allowed range")
    elif isinstance(value, str):
        if len(value.strip()) < schema.get("minLength", 0):
            errors.append(f"{path}: empty value")
        if len(value) > schema.get("maxLength", 100000):
            errors.append(f"{path}: too long")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            errors.append(f"{path}: invalid format")
        if schema.get("format") == "date" and value:
            try:
                if date.fromisoformat(value).isoformat() != value:
                    raise ValueError()
            except ValueError:
                errors.append(f"{path}: invalid ISO date")
    return errors


def validate_profile(profile: dict, base_dir: Path | None = None) -> list[str]:
    schema = read_json(ROOT / "templates/profile.schema.json")
    errors = _schema_errors(profile, schema)
    if errors:
        return errors
    for section in ("official_domains", "allowlist_domains"):
        for domain in profile.get(section, []):
            if _validate_rfc1123_fqdn(domain) != domain:
                errors.append(f"{section}: use a canonical ASCII domain: {domain!r}")
    signatory = profile["authorized_signatory"]
    if not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", signatory["legal_email"]):
        errors.append("authorized_signatory.legal_email: invalid email")
    if "public_filing_agent" in profile:
        agent = profile["public_filing_agent"]
        if not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", agent["legal_email"]):
            errors.append("public_filing_agent.legal_email: invalid email")
    urls = profile.get("official_product_urls", []) + [c["official_source_url"] for c in profile.get("copyright_originals", [])]
    if profile.get("counterfeit_warning_url"):
        urls.append(profile["counterfeit_warning_url"])
    for url in urls:
        try:
            sanitize_http_url(url)
            if not is_allowlisted_url(url, profile["official_domains"]):
                errors.append("Original/source URLs must be on an official domain")
        except ValueError:
            errors.append(f"Invalid source URL: {url!r}")
    for section in ("trademarks", "patents_and_designs"):
        for item in profile.get(section, []):
            if item.get("status", "registered") == "registered" and not item.get("reg_number", "").strip():
                errors.append(f"{section}: registered rights require reg_number")
            for key in ("cert_file_path", "drawings_file_path"):
                if item.get(key):
                    path = Path(item[key]).expanduser()
                    path = (base_dir or Path.cwd()) / path if not path.is_absolute() else path
                    try:
                        if not safe_path(path).is_file():
                            errors.append(f"{section}.{key}: not a regular file")
                    except ValueError as exc:
                        errors.append(str(exc))
    return errors


def register_brand(brand_slug: str, data_dir: Path, profile: dict, registry_path: Path = DEFAULT_REGISTRY_PATH) -> Path:
    slug = brand_slug.strip().lower()
    if not isinstance(profile, dict) or not SLUG_PATTERN.fullmatch(slug) or profile.get("brand_slug") != slug:
        raise ValueError("Brand slug must match the profile")
    data_dir = safe_path(data_dir)
    if data_dir == ROOT or ROOT in data_dir.parents:
        raise ValueError("Private brand data must be outside the skill repository")
    errors = validate_profile(profile, data_dir)
    if errors:
        raise ValueError("Invalid brand profile: " + "; ".join(errors))
    normalized = json.loads(json.dumps(profile))
    for section in ("trademarks", "patents_and_designs"):
        for item in normalized.get(section, []):
            for key in ("cert_file_path", "drawings_file_path"):
                if item.get(key):
                    path = Path(item[key]).expanduser()
                    item[key] = str(safe_path(data_dir / path if not path.is_absolute() else path))
    errors = validate_profile(normalized, data_dir)
    if errors:
        raise ValueError("Invalid brand profile: " + "; ".join(errors))
    registry_path = safe_path(registry_path)
    with locked(registry_path.with_suffix(".lock")):
        registry = read_json(registry_path) if registry_path.exists() else {"brands": {}}
        if not isinstance(registry.get("brands"), dict):
            raise ValueError("Invalid registry; restore a reviewed backup")
        for key, entry in registry["brands"].items():
            if key != slug and safe_path(Path(entry["data_dir"])) == data_dir:
                raise ConflictError("Another brand already owns this directory")
        existing = registry["brands"].get(slug)
        if existing and safe_path(Path(existing["data_dir"])) != data_dir:
            raise ConflictError("Brand relocation requires a reviewed migration")
        private_dir(data_dir)
        with locked(data_dir / ".brand.lock"):
            path = data_dir / "profile.json"
            prior = read_json(path) if path.exists() else None
            if prior and prior.get("brand_slug") != slug:
                raise ConflictError("Directory contains another brand")
            brand_id = (prior or {}).get("brand_id") or str(uuid.uuid4())
            if existing and existing.get("brand_id") not in (None, brand_id):
                raise ConflictError("Registry/profile identity mismatch")
            normalized["brand_id"] = brand_id
            normalized["allowlist_domains"] = profile_allowlist(normalized)
            atomic_write_json(path, normalized)
            private_dir(data_dir / "cases")
            private_dir(data_dir / "certificates")
            registry["brands"][slug] = {"brand_id": brand_id, "brand_name": normalized["brand_name"],
                                       "data_dir": str(data_dir), "updated_at": utc_now()}
            atomic_write_json(registry_path, registry)
    return path


def profile_from_dir(data_dir: Path) -> dict:
    profile = read_json(safe_path(data_dir) / "profile.json")
    errors = validate_profile(profile, data_dir)
    if errors or not profile.get("brand_id"):
        raise ValueError("Invalid or legacy profile; re-register after review: " + "; ".join(errors))
    return profile


def load_brand_profile(brand_slug: str, registry_path: Path = DEFAULT_REGISTRY_PATH) -> tuple[Path, dict]:
    registry_path = safe_path(registry_path)
    with locked(registry_path.with_suffix(".lock")):
        registry = read_json(registry_path)
        entry = registry["brands"][brand_slug]
        data_dir = safe_path(Path(entry["data_dir"]))
        profile = profile_from_dir(data_dir)
        if profile["brand_slug"] != brand_slug or profile["brand_id"] != entry.get("brand_id"):
            raise ConflictError("Brand registry/profile identity mismatch")
        return data_dir, profile


def _main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH)
    sub = parser.add_subparsers(dest="cmd", required=True)
    init = sub.add_parser("init")
    init.add_argument("--slug", required=True)
    init.add_argument("--data-dir", type=Path, required=True)
    init.add_argument("--profile-file", type=Path, required=True)
    val = sub.add_parser("validate")
    val.add_argument("--profile-file", type=Path, required=True)
    sub.add_parser("list")
    allow = sub.add_parser("check-allowlist")
    allow.add_argument("--slug", required=True)
    allow.add_argument("--url", required=True)
    args = parser.parse_args(argv)
    if args.cmd == "validate":
        errors = validate_profile(read_json(args.profile_file), args.profile_file.parent)
        result = {"valid": not errors, "errors": errors}
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return int(bool(errors))
    if args.cmd == "init":
        result = {"profile_path": str(register_brand(args.slug, args.data_dir, read_json(args.profile_file), args.registry))}
    elif args.cmd == "list":
        result = read_json(args.registry) if args.registry.exists() else {"brands": {}}
    else:
        _, profile = load_brand_profile(args.slug, args.registry)
        clean = sanitize_http_url(args.url)
        result = {"url": clean, "allowlisted": is_allowlisted_url(args.url, profile_allowlist(profile))}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(_main())
    except (ValueError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        sys.exit(2)
