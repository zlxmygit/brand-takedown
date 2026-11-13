"""Single-host storage for macOS, Windows and Linux.

All read/modify/write users must hold the same lock. Lock files are permanent:
unlinking one while waiters exist breaks exclusion. Windows uses byte locks and
private ACLs; POSIX uses flock, file modes and directory fsync.
"""
from __future__ import annotations

import contextlib
import errno
import json
import math
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import sys
import tempfile
import threading
import time

if os.name == "nt":
    import msvcrt
else:
    import fcntl

MAX_STATE_BYTES = 16 * 1024 * 1024


class ConflictError(ValueError):
    """A stale revision or conflicting identity was supplied."""


def validate_windows_path(value: str) -> None:
    """Reject device paths, network paths, alternate streams and ambiguous names."""
    normalized = value.replace("/", "\\")
    if normalized.startswith("\\\\"):
        raise ValueError("Use a local drive path, not a UNC or device namespace")
    drive, tail = ntpath.splitdrive(normalized)
    if drive and (not re.fullmatch(r"[a-zA-Z]:", drive) or not tail.startswith("\\")):
        raise ValueError("Drive-relative paths are not permitted")
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    reserved.update(prefix + number for prefix in ("COM", "LPT") for number in "123456789¹²³")
    for part in PureWindowsPath(tail).parts:
        if part in ("\\", ".", ".."):
            continue
        if (any(ord(c) < 32 or c in '<>:"|?*' for c in part) or part.endswith((".", " "))
                or part.split(".", 1)[0].rstrip(" ").upper() in reserved):
            raise ValueError(f"Unsafe Windows path component: {part!r}")


def safe_path(path: Path) -> Path:
    expanded = Path(path).expanduser()
    if os.name == "nt":
        validate_windows_path(str(expanded))
    path = Path(os.path.abspath(expanded))
    # Canonicalize only the known macOS root aliases, not user-created links.
    if sys.platform == "darwin" and len(path.parts) > 1 and path.parts[1] in ("tmp", "var", "etc"):
        alias, canonical = Path("/") / path.parts[1], Path("/private") / path.parts[1]
        if alias.is_symlink() and alias.resolve() == canonical:
            path = canonical.joinpath(*path.parts[2:])
    if os.name == "nt":
        from windows_security import is_remote_drive
        if is_remote_drive(path):
            raise ValueError("Use a local filesystem, not a mapped network drive")
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError(f"Symbolic links and reparse points are not permitted: {component}")
    return path.resolve(strict=False) if os.name == "nt" else path


def secure_permissions(path: Path, *, directory: bool = False) -> None:
    path = safe_path(path)
    if os.name == "nt":
        from windows_security import set_private_acl
        set_private_acl(path, directory=directory)
    else:
        os.chmod(path, 0o700 if directory else 0o600)


def private_dir(path: Path) -> Path:
    path = safe_path(path)
    if not path.exists():
        if not path.parent.exists():
            private_dir(path.parent)
        path.mkdir(mode=0o700, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"Not a directory: {path}")
    secure_permissions(path, directory=True)
    return path


def open_private_file(path: Path, *, exclusive: bool = False) -> int:
    path = safe_path(path)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    if exclusive:
        flags |= os.O_EXCL
    fd = os.open(str(path), flags, 0o600)
    try:
        os.set_inheritable(fd, False)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Expected a regular file")
        safe_path(path)
        secure_permissions(path)
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_json(path: Path) -> dict:
    path = safe_path(path)
    if path.stat().st_size > MAX_STATE_BYTES:
        raise ValueError("State file exceeds 16 MiB")
    # Windows PowerShell 5 writes a BOM for UTF-8; accept it in user JSON inputs.
    with path.open(encoding="utf-8-sig") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"Expected JSON object: {path}")
    return value


_thread_locks = {}
_lock_map_guard = threading.Lock()
_held = threading.local()


def _acquire(fd: int) -> None:
    if os.name == "nt":
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _release(fd: int) -> None:
    if os.name == "nt":
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextlib.contextmanager
def locked(path: Path, *, timeout: float = 30.0):
    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("Lock timeout must be finite and nonnegative")
    path = safe_path(path)
    private_dir(path.parent)
    # Windows case aliases must share the same in-process/reentrant lock identity.
    key = os.path.normcase(str(path))
    with _lock_map_guard:
        guard = _thread_locks.setdefault(key, threading.RLock())
    deadline = time.monotonic() + timeout
    if not guard.acquire(timeout=timeout):
        raise TimeoutError(f"Timed out acquiring file lock: {path}")
    try:
        held = getattr(_held, "paths", set())
        _held.paths = held
        if key in held:
            yield
            return
        fd = open_private_file(path)
        acquired = False
        try:
            while True:
                try:
                    _acquire(fd)
                    acquired = True
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                        raise
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Timed out acquiring file lock: {path}") from exc
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
            held.add(key)
            yield
        finally:
            held.discard(key)
            try:
                if acquired:
                    _release(fd)
            finally:
                os.close(fd)
    finally:
        guard.release()


def _replace(source: str, target: Path) -> None:
    deadline = time.monotonic() + 2.0
    while True:
        try:
            os.replace(source, target)
            return
        except PermissionError as exc:
            # A reader or virus scanner can briefly hold a Windows handle without
            # FILE_SHARE_DELETE. Do not truncate the destination while waiting.
            if os.name != "nt" or getattr(exc, "winerror", None) not in (5, 32, 33) or time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path = safe_path(path)
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".write-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            secure_permissions(Path(tmp))
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        safe_path(path)
        _replace(tmp, path)
        if os.name != "nt":
            directory_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def atomic_write_json(path: Path, payload: dict) -> None:
    content = (json.dumps(payload, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")
    if len(content) > MAX_STATE_BYTES:
        raise ValueError("State write exceeds 16 MiB; previous file preserved")
    atomic_write_bytes(path, content)
