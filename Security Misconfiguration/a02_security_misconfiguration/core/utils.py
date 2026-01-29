"""Utility helpers used across checks."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import ssl
import time
from typing import Dict, Iterable, List, Optional, Tuple

import requests
from requests.adapters import HTTPAdapter


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_target(target: str) -> str:
    """Normalize target to include scheme if it looks like a hostname."""
    t = target.strip()
    if re.match(r"^https?://", t, re.IGNORECASE):
        return t
    # If it contains a slash or a colon like host:port, treat as URL-ish.
    if "/" in t:
        return "http://" + t
    # Plain host/ip -> default http
    return "http://" + t


def requests_session(user_agent: str) -> requests.Session:
    """Create a Session with sane defaults for scanning.

    - Connection pooling improves performance during high request counts.
    - Default headers reduce trivial WAF blocks and improve content negotiation.
    """

    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Connection": "keep-alive",
        }
    )

    # Adapter Tuning: increase pool sizes for aggressive fuzzing.
    adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=0)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def http_request(
    session: requests.Session,
    method: str,
    url: str,
    *,
    timeout: Tuple[float, float],
    allow_redirects: bool = True,
    max_redirects: int = 5,
    max_bytes: Optional[int] = None,
    **kwargs,
) -> requests.Response:
    """HTTP request with bounded redirects.

    max_bytes:
        If set, requests the first N bytes via Range to reduce bandwidth/memory
        during broad fuzzing. This is best-effort: servers may ignore it.
    """

    # requests has its own redirect handling; we limit via session.max_redirects
    old = session.max_redirects
    session.max_redirects = max_redirects
    try:
        headers = dict(kwargs.pop("headers", {}) or {})
        if max_bytes is not None and max_bytes > 0 and "Range" not in headers:
            headers["Range"] = f"bytes=0-{int(max_bytes) - 1}"

        return session.request(
            method,
            url,
            timeout=timeout,
            allow_redirects=allow_redirects,
            verify=False,  # aggressive scanning often hits self-signed; caller should interpret
            headers=headers,
            **kwargs,
        )
    finally:
        session.max_redirects = old


def tcp_connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def tcp_banner(
    host: str, port: int, timeout: float, read_bytes: int = 2048
) -> str:
    """Try to read a banner from a TCP service."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                # Some services respond after a newline.
                s.sendall(b"\r\n")
            except Exception:
                pass
            data = s.recv(read_bytes)
            return data.decode("utf-8", errors="replace")
    except Exception as e:
        return f"<no_banner:{type(e).__name__}:{e}>"


def resolve_host_from_url(url: str) -> str:
    """Extract hostname from a URL."""
    from urllib.parse import urlparse

    p = urlparse(url)
    return p.hostname or url


def port_scan(
    host: str,
    ports: Iterable[int],
    *,
    timeout: float,
    workers: int = 200,
) -> List[int]:
    """TCP connect scan.

    Implementation note:
    Avoid submitting tens of thousands of futures at once (memory spike). We scan
    in chunks to keep the executor queue bounded.
    """

    open_ports: List[int] = []

    def _probe(p: int) -> Optional[int]:
        return p if tcp_connect(host, p, timeout) else None

    ports_list = list(ports)
    chunk_size = max(500, min(5000, workers * 10))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for i in range(0, len(ports_list), chunk_size):
            batch = ports_list[i : i + chunk_size]
            futs = [ex.submit(_probe, p) for p in batch]
            for f in concurrent.futures.as_completed(futs):
                r = f.result()
                if r is not None:
                    open_ports.append(r)

    return sorted(open_ports)


def chunked(seq: List[str], n: int) -> List[List[str]]:
    return [seq[i : i + n] for i in range(0, len(seq), n)]


def looks_like_directory_listing(body: str) -> bool:
    """Heuristic detection for directory listing pages."""
    b = body.lower()
    patterns = [
        "index of /",
        "directory listing for",
        "parent directory",
        "<title>index of",
    ]
    return any(p in b for p in patterns)


def is_verbose_error(body: str) -> bool:
    b = body.lower()
    patterns = [
        "traceback (most recent call last)",
        "stack trace",
        "exception in thread",
        "fatal error",
        "warning:",
        "org.springframework",
        "django debug",
        "werkzeug debugger",
    ]
    return any(p in b for p in patterns)


def safe_truncate(s: str, limit: int = 4000) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + "\n...<truncated>..."


def sleep_backoff(attempt: int, base: float = 0.3, cap: float = 2.0) -> None:
    t = min(cap, base * (2**attempt))
    time.sleep(t)


def tls_probe(host: str, port: int, timeout: float, server_name: Optional[str] = None) -> Dict[str, str]:
    """Best-effort TLS probe returning protocol/cipher/cert summary."""
    out: Dict[str, str] = {}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name or host) as ssock:
                out["protocol"] = ssock.version() or "unknown"
                c = ssock.cipher()
                out["cipher"] = "-".join(str(x) for x in c) if c else "unknown"
                cert = ssock.getpeercert()
                if cert:
                    out["cert_subject"] = str(cert.get("subject"))
                    out["cert_issuer"] = str(cert.get("issuer"))
                    out["cert_notAfter"] = str(cert.get("notAfter"))
    except Exception as e:
        out["error"] = f"{type(e).__name__}: {e}"
    return out
