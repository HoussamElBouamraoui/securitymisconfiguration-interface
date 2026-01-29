"""Aggressive detection for SMB/FTP/Telnet/etc exposure (no exploitation)."""

from __future__ import annotations

from .shared import host_from_target
from ..core.base_check import BaseCheck
from ..core.result import ScanResult
from ..core.utils import port_scan, safe_truncate, tcp_banner


SERVICE_PROBES = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    139: "NetBIOS",
}


class SMBFTPEtcDetection(BaseCheck):
    scan_type = "A02_SMB_FTP_Etc_Detection"

    def run(self, target: str) -> ScanResult:
        res = self._result(target)
        host = host_from_target(target)
        ports = list(SERVICE_PROBES.keys())
        open_ports = port_scan(host, ports, timeout=self.config.connect_timeout, workers=100)

        if open_ports:
            # Telnet/SMB are typically higher impact.
            sev = "HIGH" if any(p in (23, 445) for p in open_ports) else "MEDIUM"
            res.severity = sev
            res.confidence = "high"

            details = []
            for p in open_ports:
                banner = tcp_banner(host, p, self.config.read_timeout, self.config.banner_read_bytes)
                details.append(f"{p}/{SERVICE_PROBES[p]} banner={safe_truncate(banner, 300)}")

            res.add_finding(
                title="Legacy/file-sharing services exposed",
                severity=sev,
                confidence="high",
                risk="Legacy services (Telnet/SMB/FTP) can increase risk of plaintext auth, data exposure, and lateral movement.",
                evidence=safe_truncate("; ".join(details), 4000),
                recommendation="Disable unused legacy services and restrict access via firewall/VPN/allowlists; enforce strong authentication and modern protocols.",
                confidence_reason="Direct evidence: TCP ports accepted connections and banners were retrieved (best-effort for banner content).",
            )
            res.metadata["exposed_ports"] = open_ports

        res.evidence = safe_truncate(f"Probed {ports}; open: {open_ports}")
        res.metadata["host"] = host
        return res
