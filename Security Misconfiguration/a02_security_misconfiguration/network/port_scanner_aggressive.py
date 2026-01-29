"""Aggressive TCP port scanner (connect scan) for A02 misconfiguration.

Note: A full 1-65535 scan can be slow/noisy. You can tune via CheckConfig.
"""

from __future__ import annotations

from .shared import host_from_target
from ..core.base_check import BaseCheck
from ..core.result import ScanResult
from ..core.utils import port_scan, safe_truncate


class PortScannerAggressive(BaseCheck):
    scan_type = "A02_Port_Scanner_Aggressive"

    def run(self, target: str) -> ScanResult:
        res = self._result(target)
        host = host_from_target(target)

        ports = list(range(1, self.config.port_scan_max_ports + 1))
        open_ports = port_scan(
            host,
            ports,
            timeout=self.config.connect_timeout,
            workers=self.config.port_scan_workers,
        )
        res.metadata["open_ports"] = open_ports
        res.metadata["host"] = host

        if open_ports:
            res.severity = "MEDIUM"
            res.confidence = "high"
            res.add_finding(
                title="Open TCP ports detected",
                severity="MEDIUM",
                confidence="high",
                risk="One or more reachable ports increase the exposed attack surface.",
                evidence=safe_truncate(str(open_ports)),
                recommendation="Close unused ports and restrict access through firewall/allowlists or network segmentation.",
                confidence_reason="Direct evidence: TCP ports accepted connections during connect-scan.",
            )

        res.evidence = safe_truncate(f"Scanned {len(ports)} ports; open: {open_ports}")
        return res
