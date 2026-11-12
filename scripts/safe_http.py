"""Bounded, direct HTTP with public-address pinning and per-hop policy checks.

No proxy, cookie jar, ambient curl config, authentication or browser execution.
Redirect policy is enforced before resolving/contacting every destination.
"""
from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import socket
import subprocess
import sys
import json
import ssl
import time
import threading
from urllib.parse import urljoin, urlsplit

from brand_registry import is_allowlisted_url, sanitize_http_url

MAX_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 5


class NetworkPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class FetchResult:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    peer_ip: str
    hops: tuple
    tls_sha256: str = ""


def resolve_addresses(host: str, port: int, timeout=5.0) -> list[str]:
    # Isolated child bounds OS resolver latency; socket timeouts do not bound getaddrinfo.
    command = [sys.executable, "-I", "-S", "-c",
               "import json,socket,sys; print(json.dumps(sorted({r[4][0] for r in socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)})))",
               host, str(port)]
    try:
        result = subprocess.run(command, capture_output=True, timeout=min(5.0, timeout), check=True)
        addresses = json.loads(result.stdout)
    except (subprocess.SubprocessError, ValueError, OSError) as exc:
        raise OSError("DNS lookup failed or exceeded five seconds") from exc
    if not isinstance(addresses, list) or not all(isinstance(ip, str) for ip in addresses):
        raise OSError("Invalid DNS resolver response")
    return addresses


def public_addresses(host: str, port: int, timeout=5.0) -> list[str]:
    addresses = resolve_addresses(host, port, timeout=timeout)
    if not addresses:
        raise NetworkPolicyError("No resolved address")
    for raw in addresses:
        ip = ipaddress.ip_address(raw)
        transition = isinstance(ip, ipaddress.IPv6Address) and (
            ip.ipv4_mapped is not None or ip.sixtofour is not None or ip.teredo is not None
            or ip in ipaddress.ip_network("64:ff9b::/96") or ip in ipaddress.ip_network("64:ff9b:1::/48"))
        if not ip.is_global or ip.is_multicast or ip.is_unspecified or transition:
            raise NetworkPolicyError("Destination resolves to a non-public address")
    return addresses


def _connection(host: str, port: int, ip: str, secure: bool, timeout: float):
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    started = time.monotonic()
    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        raw.settimeout(max(0.001, timeout - (time.monotonic() - started)))
        if raw.getpeername()[0] != ip:
            raise NetworkPolicyError("Connected peer differs from pinned address")
        connection.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=host) if secure else raw
        return connection
    except BaseException:
        raw.close()
        raise


def _fetch(url: str, allowlist_domains=(), *, max_bytes=MAX_BYTES, timeout=25.0,
          method="GET", proxy=None, referer=None) -> FetchResult:
    if proxy:
        raise NetworkPolicyError("Proxy mode disabled: egress policy cannot be guaranteed")
    if method not in ("GET", "HEAD"):
        raise NetworkPolicyError("Only read-only GET/HEAD supported")
    if max_bytes < 1 or max_bytes > MAX_BYTES or timeout <= 0 or timeout > 60:
        raise ValueError("Invalid resource budget")
    # An ad referer can expose data and is unnecessary for this safe-mode fetcher.
    if referer:
        raise NetworkPolicyError("Referer spoofing disabled in safe mode")
    started = time.monotonic()
    hops = []
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        if time.monotonic() - started >= timeout:
            raise TimeoutError("Fetch deadline exceeded")
        current = sanitize_http_url(current)
        if is_allowlisted_url(current, list(allowlist_domains)):
            raise NetworkPolicyError("Redirect/target matches official or authorized domain")
        parsed = urlsplit(current)
        if parsed.hostname.endswith((".localhost", ".local", ".internal", ".home.arpa")):
            raise NetworkPolicyError("Local namespace is not supported")
        port = 443 if parsed.scheme == "https" else 80
        addresses = public_addresses(parsed.hostname, port, timeout=min(5.0, max(0.001, timeout - (time.monotonic() - started))))
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError("Fetch deadline exceeded")
        ip = addresses[0]
        conn = _connection(parsed.hostname, port, ip, parsed.scheme == "https", remaining)
        active_socket = None
        def abort_socket():
            target = active_socket or conn.sock
            if target is not None:
                try:
                    target.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        timer = threading.Timer(max(0.001, timeout - (time.monotonic() - started)), abort_socket)
        timer.daemon = True
        timer.start()
        try:
            fingerprint = ""
            if parsed.scheme == "https":
                import hashlib
                fingerprint = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
            path = parsed.path + ("?" + parsed.query if parsed.query else "")
            conn.request(method, path, headers={"User-Agent": "BrandTakedownEvidence/2.0", "Accept-Encoding": "identity", "Connection": "close"})
            active_socket = conn.sock
            response = conn.getresponse()
            headers = {key.lower(): value for key, value in response.getheaders()}
            hops.append({"url": current, "status": response.status, "peer_ip": ip})
            if response.status in (301, 302, 303, 307, 308):
                if not headers.get("location"):
                    raise NetworkPolicyError("Redirect missing Location")
                nxt = urljoin(current, headers["location"])
                if parsed.scheme == "https" and urlsplit(nxt).scheme != "https":
                    raise NetworkPolicyError("HTTPS downgrade rejected")
                current = nxt
                continue
            if headers.get("content-encoding", "identity").lower() != "identity":
                raise NetworkPolicyError("Compressed responses are not accepted")
            if "content-length" in headers and int(headers["content-length"]) > max_bytes:
                raise NetworkPolicyError("Response exceeds size budget")
            chunks, total = [], 0
            if method != "HEAD":
                while True:
                    if response.isclosed():
                        break
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        raise TimeoutError("Fetch deadline exceeded")
                    if active_socket is not None and active_socket.fileno() >= 0:
                        active_socket.settimeout(remaining)
                    chunk = response.read1(min(65536, max_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_bytes:
                        raise NetworkPolicyError("Response exceeds size budget")
                    chunks.append(chunk)
            if method != "HEAD" and "content-length" in headers and total != int(headers["content-length"]):
                raise NetworkPolicyError("Truncated response body")
            return FetchResult(current, response.status, headers, b"".join(chunks), ip, tuple(hops), fingerprint)
        finally:
            timer.cancel()
            conn.close()
    raise NetworkPolicyError("Too many redirects")


def fetch(url: str, allowlist_domains=(), **kwargs) -> FetchResult:
    try:
        return _fetch(url, allowlist_domains, **kwargs)
    except http.client.HTTPException as exc:
        raise OSError("Malformed or incomplete HTTP response") from exc
