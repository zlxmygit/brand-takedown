"""Transactional reviewed-candidate archive and indexed suppression.

The archive commits before the active JSON is pruned. Recovery removes only exact
archived copies, so an interrupted prune never loses a decision or a pending item.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import uuid

from brand_registry import normalize_hostname, profile_from_dir, utc_now
from storage import atomic_write_json, locked, read_json, safe_path, open_private_file, secure_permissions

REVIEWED = frozenset(("REJECTED", "AUTHORIZED", "CONFIRMED_FOR_REVIEWED_CASE"))
MAX_BATCH = 1000


def _encode(entry: dict) -> str:
    return json.dumps(entry, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@contextlib.contextmanager
def _database(brand_dir: Path, *, create: bool = False):
    path = safe_path(brand_dir / "radar-archive.sqlite3")
    for suffix in ("-journal", "-wal", "-shm"):
        safe_path(Path(str(path) + suffix))
    if not path.exists() and not create:
        yield None
        return
    if not path.exists():
        fd = open_private_file(path, exclusive=True)
        os.close(fd)
    if not path.is_file():
        raise ValueError("Radar archive must be a regular file")
    secure_permissions(path)
    db = None
    try:
        db = sqlite3.connect(str(path), timeout=10)
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        with db:
            db.execute("CREATE TABLE IF NOT EXISTS identity (brand_id TEXT PRIMARY KEY)")
            db.execute("CREATE TABLE IF NOT EXISTS batches (batch_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, reviewer TEXT NOT NULL, count INTEGER NOT NULL, sha256 TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS entries (batch_id TEXT NOT NULL, domain TEXT NOT NULL, payload TEXT NOT NULL, sha256 TEXT NOT NULL, PRIMARY KEY (batch_id, domain))")
            db.execute("CREATE TABLE IF NOT EXISTS suppressed (domain TEXT PRIMARY KEY, batch_id TEXT NOT NULL)")
            brand_id = profile_from_dir(brand_dir)["brand_id"]
            ids = [row[0] for row in db.execute("SELECT brand_id FROM identity")]
            if not ids:
                db.execute("INSERT INTO identity VALUES (?)", (brand_id,))
            elif ids != [brand_id]:
                raise ValueError("Radar archive belongs to another brand")
        yield db
    except sqlite3.Error as exc:
        raise ValueError(f"Radar archive database error: {exc}") from exc
    finally:
        if db is not None:
            db.close()


def _matching(db, domains):
    if db is None:
        return
    domains = list(domains)
    for start in range(0, len(domains), 400):
        chunk = domains[start:start + 400]
        sql = ("SELECT s.domain,e.payload,e.sha256 FROM suppressed s LEFT JOIN entries e "
               "ON e.domain=s.domain AND e.batch_id=s.batch_id WHERE s.domain IN (" + ",".join("?" for _ in chunk) + ")")
        for domain, payload, digest in db.execute(sql, chunk):
            if payload is None or _sha(payload) != digest:
                raise ValueError("Radar archive integrity mismatch")
            yield domain, payload


def recover_pruned_state(brand_dir: Path, state: dict) -> int:
    """Caller holds .radar.lock; only remove byte-identical committed copies."""
    removed = []
    with _database(brand_dir) as db:
        for domain, payload in _matching(db, state["candidates"]):
            if _encode(state["candidates"][domain]) == payload:
                removed.append(domain)
    for domain in removed:
        del state["candidates"][domain]
    return len(removed)


def suppressed_domains(brand_dir: Path, domains) -> set[str]:
    with _database(brand_dir) as db:
        return {domain for domain, _ in _matching(db, domains)}


def archive_reviewed(brand_dir: Path, reviewer: str, limit: int = MAX_BATCH) -> dict:
    brand_dir = safe_path(brand_dir)
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 200:
        raise ValueError("Named archive reviewer required (up to 200 characters)")
    if type(limit) is not int or not 1 <= limit <= MAX_BATCH:
        raise ValueError("Archive limit must be 1..1000")
    path = brand_dir / "radar_seen.json"
    with locked(brand_dir / ".radar.lock"):
        state = read_json(path)
        if state.get("schema_version") != 2 or not isinstance(state.get("candidates"), dict):
            raise ValueError("Unsupported radar state")
        recovered = recover_pruned_state(brand_dir, state)
        selected = sorted((d, e) for d, e in state["candidates"].items() if e.get("status") in REVIEWED)[:limit]
        for domain, entry in selected:
            if normalize_hostname(domain) != domain or not entry.get("reviewer") or not entry.get("rationale"):
                raise ValueError("Archive only canonical domains with a recorded reviewer and rationale")
        if not selected:
            if recovered:
                atomic_write_json(path, state)
            return {"archived_count": 0, "recovered_count": recovered, "remaining_count": len(state["candidates"])}
        batch_id = "ARCH-" + uuid.uuid4().hex
        payloads = [(domain, _encode(entry)) for domain, entry in selected]
        digest = _sha(_encode({"entries": {d: json.loads(p) for d, p in payloads}}))
        with _database(brand_dir, create=True) as db, db:
            db.execute("INSERT INTO batches VALUES (?,?,?,?,?)", (batch_id, utc_now(), reviewer.strip(), len(selected), digest))
            for domain, payload in payloads:
                db.execute("INSERT INTO entries VALUES (?,?,?,?)", (batch_id, domain, payload, _sha(payload)))
                db.execute("INSERT OR REPLACE INTO suppressed VALUES (?,?)", (domain, batch_id))
        # Database commit is durable before any active entry is removed.
        for domain, _ in selected:
            del state["candidates"][domain]
        atomic_write_json(path, state)
        return {"batch_id": batch_id, "sha256": digest, "archived_count": len(selected),
                "recovered_count": recovered, "remaining_count": len(state["candidates"])}


def export_batch(brand_dir: Path, batch_id: str) -> dict:
    with locked(brand_dir / ".radar.lock"), _database(brand_dir) as db:
        row = db.execute("SELECT created_at,reviewer,count,sha256 FROM batches WHERE batch_id=?", (batch_id,)).fetchone() if db else None
        if row is None:
            raise ValueError("Unknown archive batch")
        payloads = {}
        for domain, payload, digest in db.execute("SELECT domain,payload,sha256 FROM entries WHERE batch_id=? ORDER BY domain", (batch_id,)):
            if payload is None or _sha(payload) != digest:
                raise ValueError("Radar archive integrity mismatch")
            payloads[domain] = payload
        if len(payloads) != row[2] or _sha(_encode({"entries": {d: json.loads(p) for d, p in payloads.items()}})) != row[3]:
            raise ValueError("Radar archive batch mismatch")
        return {"batch_id": batch_id, "created_at": row[0], "reviewer": row[1], "count": row[2],
                "sha256": row[3], "entries": {k: json.loads(v) for k, v in payloads.items()}}


def restore_candidate(brand_dir: Path, domain: str, reviewer: str, rationale: str) -> dict:
    """Explicit re-review; a changed site may justify reopening an archived decision."""
    host = normalize_hostname(domain)
    if not host or not reviewer.strip() or not rationale.strip() or len(reviewer) > 200 or len(rationale) > 4000:
        raise ValueError("Valid domain, reviewer and rationale required")
    path = safe_path(brand_dir) / "radar_seen.json"
    with locked(brand_dir / ".radar.lock"), _database(brand_dir) as db:
        rows = list(_matching(db, [host]))
        if not rows:
            raise ValueError("Domain is not archived")
        state = read_json(path)
        if host in state["candidates"] and state["candidates"][host].get("status") == "PENDING_REVIEW":
            return state["candidates"][host]
        from ct_radar import MAX_RADAR_CANDIDATES
        if host not in state["candidates"] and len(state["candidates"]) >= MAX_RADAR_CANDIDATES:
            raise ValueError("Archive reviewed records to free active capacity first")
        original = json.loads(rows[0][1])
        entry = {"status": "PENDING_REVIEW", "first_seen_at": original["first_seen_at"], "last_seen_at": utc_now(),
                 "restored_by": reviewer.strip(), "restore_reason": rationale.strip(), "restored_at": utc_now()}
        state["candidates"][host] = entry
        # Keep the suppression index: scans retain explicit active entries; a later
        # archive creates a new immutable decision and updates the indexed pointer.
        atomic_write_json(path, state)
        return entry
