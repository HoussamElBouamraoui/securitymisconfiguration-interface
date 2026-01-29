"""Fetch and analyze service banners for information leakage (versions/debug)."""

from __future__ import annotations

import re

from .default_services_detection import DEFAULT_SERVICE_PORTS
from .shared import host_from_target
from ..core.base_check import BaseCheck
from ..core.result import ScanResult
from ..core.utils import port_scan, safe_truncate, tcp_banner


VERSION_RE = re.compile(r"(\d+\.){1,3}\d+")
DEBUG_HINTS = ["debug", "dev", "stack trace", "test environment"]


class BannerAnalysis(BaseCheck):
    scan_type = "A02_Banner_Analysis"

    def run(self, target: str) -> ScanResult:
        res = self._result(target)
        host = host_from_target(target)
        ports = list(DEFAULT_SERVICE_PORTS.keys())
        open_ports = port_scan(host, ports, timeout=self.config.connect_timeout, workers=200)

        leaks = []
        raw = []
        for p in open_ports:
            banner = tcp_banner(host, p, self.config.read_timeout, self.config.banner_read_bytes)
            raw.append(f"[{p}] {banner}")
            b = banner.lower()
            has_version = bool(VERSION_RE.search(banner))
            has_debug = any(h in b for h in DEBUG_HINTS)
            if has_version or has_debug:
                leaks.append(
                    {
                        "port": p,
                        "service": DEFAULT_SERVICE_PORTS.get(p, "unknown"),
                        "banner": safe_truncate(banner, 600),
                        "version_hint": has_version,
                        "debug_hint": has_debug,
                    }
                )

        if leaks:
            # Higher severity if explicit debug hints are present
            sev = "MEDIUM" if any(x.get("debug_hint") for x in leaks) else "LOW"
            res.severity = sev
            res.confidence = "medium"

            res.add_finding(
                title="Information leakage via banners",
                severity=sev,
                confidence="medium",
                risk="Service banners may disclose versions or debug hints, helping attackers target known vulnerabilities.",
                evidence=safe_truncate(str(leaks), 6000),
                recommendation="Minimize banner/version exposure and disable debug information on network services.",
                confidence_reason="Best-effort detection based on banner content heuristics; manual validation recommended.",
            )
            res.metadata["banner_leaks"] = leaks

        res.evidence = safe_truncate("\n".join(raw), 8000)
        res.metadata["host"] = host
        res.metadata["open_ports"] = open_ports
        return res
