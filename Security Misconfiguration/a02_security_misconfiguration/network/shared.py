"""Shared helpers for network checks."""

from __future__ import annotations

from ..core.utils import normalize_target, resolve_host_from_url


def host_from_target(target: str) -> str:
    """Accept URL or host/IP and return a hostname/IP for TCP scanning."""
    t = normalize_target(target)
    return resolve_host_from_url(t)
