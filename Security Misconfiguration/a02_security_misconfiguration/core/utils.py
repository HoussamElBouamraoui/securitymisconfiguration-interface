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


def _top_tcp_ports() -> List[int]:
    """Liste courte de ports TCP fréquents (ordre approximatif de probabilité).

    Objectif: donner une couverture utile en peu de temps pour éviter les timeouts.
    """

    # Inspiré des ports les plus communs (Nmap top ports / usages courants).
    # On garde une liste raisonnable (<= 200) pour rester rapide.
    return [
        21,
        22,
        23,
        25,
        53,
        67,
        68,
        69,
        80,
        81,
        82,
        83,
        88,
        110,
        111,
        123,
        135,
        137,
        138,
        139,
        143,
        161,
        389,
        443,
        445,
        465,
        587,
        631,
        636,
        873,
        902,
        989,
        990,
        993,
        995,
        1080,
        1194,
        1433,
        1521,
        1723,
        1883,
        2049,
        2375,
        2376,
        2483,
        2484,
        3000,
        3128,
        3268,
        3269,
        3306,
        3389,
        3690,
        4000,
        4040,
        4369,
        5000,
        5001,
        5060,
        5061,
        5432,
        5672,
        5900,
        5985,
        5986,
        6000,
        6379,
        6443,
        6667,
        7001,
        7077,
        7199,
        7474,
        7687,
        8000,
        8008,
        8010,
        8080,
        8081,
        8086,
        8088,
        8090,
        8181,
        8443,
        8530,
        8531,
        8778,
        8888,
        9000,
        9042,
        9080,
        9090,
        9092,
        9100,
        9200,
        9300,
        9418,
        9443,
        9999,
        10000,
        11211,
        15672,
        16010,
        18080,
        27017,
    ]


def select_ports_for_scan(max_port_inclusive: int, *, prefer_top: bool = True) -> List[int]:
    """Construit une liste de ports à scanner.

    - prefer_top=True: on scanne d'abord les ports fréquents, puis le reste (1..max).
    - prefer_top=False: scan séquentiel 1..max.
    """

    m = int(max(1, max_port_inclusive))
    if not prefer_top:
        return list(range(1, m + 1))

    top = [p for p in _top_tcp_ports() if 1 <= p <= m]
    top_set = set(top)
    rest = [p for p in range(1, m + 1) if p not in top_set]
    return top + rest


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


def port_scan_timeboxed(
    host: str,
    ports: Iterable[int],
    *,
    timeout: float,
    workers: int = 200,
    timebox_seconds: Optional[float] = None,
) -> Tuple[List[int], Dict[str, float]]:
    """TCP connect scan borné par une timebox.

    Retourne: (open_ports, stats)

    stats contient:
      - scanned: nombre de ports effectivement *soumis* (approx stable)
      - elapsed_seconds
      - timeboxed: 1.0 si coupé par timebox, sinon 0.0

    Implémentation:
    - Par "fenêtre" (in-flight futures) pour éviter de soumettre 10k+ tâches.
    - Réévalue la deadline fréquemment via wait(timeout=...).
    - À la deadline, on arrête de soumettre de nouveaux ports et on tente d'annuler
      les futures pas encore démarrées (best-effort).

    Important:
    On ne peut pas interrompre proprement un socket connect déjà en cours dans un thread
    Python; d'où l'importance d'un connect_timeout bas (ex: 0.5-3s) et d'une fenêtre
    limitée.
    """

    open_ports: List[int] = []
    scanned_submitted = 0
    start = time.time()
    deadline = (start + float(timebox_seconds)) if timebox_seconds and timebox_seconds > 0 else None
    timeboxed_flag = False

    def _probe(p: int) -> Optional[int]:
        return p if tcp_connect(host, p, timeout) else None

    ports_list = list(ports)

    # Fenêtre de futures en vol : bornée pour rester réactive et réduire la mémoire.
    # On borne aussi pour éviter des valeurs absurdes en mode offensif.
    workers = int(max(1, workers))
    max_in_flight = max(10, min(5000, workers * 2))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        pending: set[concurrent.futures.Future] = set()
        idx = 0

        while idx < len(ports_list) or pending:
            now = time.time()
            if deadline is not None and now >= deadline:
                timeboxed_flag = True
                # Stop submitting new ports.
                break

            # Remplir la fenêtre tant qu'il reste des ports et de la place.
            while idx < len(ports_list) and len(pending) < max_in_flight:
                if deadline is not None and time.time() >= deadline:
                    timeboxed_flag = True
                    break
                p = int(ports_list[idx])
                idx += 1
                pending.add(ex.submit(_probe, p))
                scanned_submitted += 1

            if not pending:
                continue

            # Attendre un peu pour récupérer des résultats tout en restant réactif.
            # Si on a une deadline, on ne dépasse pas le temps restant.
            wait_timeout = 0.2
            if deadline is not None:
                remaining = max(0.0, deadline - time.time())
                wait_timeout = min(wait_timeout, remaining)

            done, pending = concurrent.futures.wait(
                pending,
                timeout=wait_timeout,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )

            for f in done:
                try:
                    r = f.result()
                except Exception:
                    r = None
                if r is not None:
                    open_ports.append(int(r))

        # Deadline atteinte: annulation best-effort des tâches pas encore démarrées.
        if timeboxed_flag and pending:
            for f in list(pending):
                try:
                    f.cancel()
                except Exception:
                    pass

    elapsed = max(0.0, time.time() - start)
    stats = {
        "scanned": float(scanned_submitted),
        "elapsed_seconds": float(elapsed),
        "timeboxed": 1.0 if timeboxed_flag else 0.0,
    }
    return sorted(set(open_ports)), stats


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
