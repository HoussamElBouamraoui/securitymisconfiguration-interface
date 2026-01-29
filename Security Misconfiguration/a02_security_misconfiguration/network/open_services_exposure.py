"""Analyze exposure risk for open services using heuristics."""

from __future__ import annotations

from .default_services_detection import DEFAULT_SERVICE_PORTS
from .shared import host_from_target
from ..core.base_check import BaseCheck
from ..core.result import ScanResult
from ..core.utils import port_scan, safe_truncate


HIGH_RISK_PORTS = {
    23: "Telnet (plaintext auth)",
    445: "SMB (file sharing)",
    3389: "RDP (remote desktop)",
    6379: "Redis (often unauth)",
    9200: "Elasticsearch (data exposure)",
    27017: "MongoDB (data exposure)",
}


class OpenServicesExposure(BaseCheck):
    scan_type = "A02_Open_Services_Exposure"

    def run(self, target: str) -> ScanResult:
        res = self._result(target)
        host = host_from_target(target)

        ports = sorted(set(DEFAULT_SERVICE_PORTS.keys()) | set(HIGH_RISK_PORTS.keys()))
        open_ports = port_scan(host, ports, timeout=self.config.connect_timeout, workers=200)

        risky = [p for p in open_ports if p in HIGH_RISK_PORTS]
        if risky:
            res.severity = "HIGH"
            res.confidence = "high"
            details = [f"{p} ({HIGH_RISK_PORTS[p]})" for p in risky]
            res.add_finding(
                title="High-risk services exposed",
                severity="HIGH",
                confidence="high",
                risk="Sensitive management/data services reachable from the network may indicate missing segmentation.",
                evidence=safe_truncate(", ".join(details)),
                recommendation="Restrict access via firewall/VPN/allowlists and require strong authentication; disable unused services.",
                confidence_reason="Direct evidence: TCP ports accepted connections (reachable services).",
            )
            res.metadata["high_risk_ports"] = risky
        elif open_ports:
            res.severity = "MEDIUM"
            res.confidence = "high"
            res.add_finding(
                title="Network services exposed",
                severity="MEDIUM",
                confidence="high",
                risk="Unnecessary exposure increases attack surface.",
                evidence=safe_truncate(str(open_ports)),
                recommendation="Restrict access and harden/decommission unused services.",
                confidence_reason="Direct evidence: TCP ports accepted connections.",
            )
            res.metadata["open_ports"] = open_ports

        res.evidence = safe_truncate(f"Scanned common/risky ports: {ports}; open: {open_ports}")
        res.metadata["host"] = host
        return res
