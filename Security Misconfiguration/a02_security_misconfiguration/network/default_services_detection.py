"""Detect exposed default/admin services by port heuristics."""

from __future__ import annotations

from .shared import host_from_target
from ..core.base_check import BaseCheck
from ..core.result import ScanResult
from ..core.utils import port_scan, safe_truncate


DEFAULT_SERVICE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

HIGHER_RISK = {23, 445, 3389, 6379, 9200, 27017}


class DefaultServicesDetection(BaseCheck):
    scan_type = "A02_Default_Services_Detection"

    def run(self, target: str) -> ScanResult:
        res = self._result(target)
        host = host_from_target(target)
        ports = list(DEFAULT_SERVICE_PORTS.keys())
        open_ports = port_scan(
            host,
            ports,
            timeout=self.config.connect_timeout,
            workers=min(self.config.port_scan_workers, 200),
        )

        if open_ports:
            res.severity = "HIGH" if any(p in HIGHER_RISK for p in open_ports) else "MEDIUM"
            res.confidence = "high"

            services = [f"{p}/{DEFAULT_SERVICE_PORTS.get(p,'unknown')}" for p in open_ports]
            res.add_finding(
                title="Default/common services exposed",
                severity=res.severity,
                confidence="high",
                risk="Common network services are exposed; some may be misconfigured or unnecessary.",
                evidence=safe_truncate(", ".join(services)),
                recommendation="Restrict exposure with firewall/VPN, disable unused services, and harden authentication/configuration.",
                confidence_reason="Direct evidence: TCP ports accepted connections (open ports).",
            )
            res.metadata["open_services"] = services

        res.evidence = safe_truncate(f"Probed ports: {ports}; open: {open_ports}")
        res.metadata["host"] = host
        return res
