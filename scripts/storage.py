"""Single-host POSIX storage: private files, process locks, durable atomic writes.

Not a distributed database. All read/modify/write users must hold the same lock.
Lock files are permanent: unlinking one while waiters exist breaks exclusion.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import sys
from pathlib import Path
import tempfile
import threading


class ConflictError(ValueError):
    """A stale revision or conflicting identity was supplied."""


def safe_path(path: Path) -> Path:
    path = Path(os.path.abspath(path.expanduser()))
    # macOS uses OS-owned /var and /tmp aliases; do not reject its normal temp paths.
    # Only these exact root aliases are canonicalized, never user-created symlinks.
    if sys.platform == "darwin" and len(path.parts) > 1 and path.parts[1] in ("tmp", "var", "etc"):
        alias = Path("/") / path.parts[1]
        canonical = Path("/private") / path.parts[1]
        if alias.is_symlink() and alias.resolve() == canonical:
            path = canonical.joinpath(*path.parts[2:])
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError(f"Symbolic links are not permitted: {component}")
    return path


def private_dir(path: Path) -> Path:
    path = safe_path(path)
    if not path.exists():
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"Not a directory: {path}")
    os.chmod(path, 0o700)
    return path


def read_json(path: Path) -> dict:
    path = safe_path(path)
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("State file exceeds 16 MiB")
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


_thread_locks = {}
_lock_map_guard = threading.Lock()
_held = threading.local()


@contextlib.contextmanager
def locked(path: Path):
    path = safe_path(path)
    private_dir(path.parent)
    with _lock_map_guard:
        guard = _thread_locks.setdefault(str(path), threading.RLock())
    with guard:
        held = getattr(_held, "paths", set())
        _held.paths = held
        if str(path) in held:
            yield
            return
        fd = os.open(str(path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            held.add(str(path))
            yield
        finally:
            held.discard(str(path))
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path = safe_path(path)
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".write-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def atomic_write_json(path: Path, payload: dict) -> None:
    atomic_write_bytes(path, (json.dumps(payload, ensure_ascii=False, indent=2,
                                       allow_nan=False) + "\n").encode("utf-8"))
