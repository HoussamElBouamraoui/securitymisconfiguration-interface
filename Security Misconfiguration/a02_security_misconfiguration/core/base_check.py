"""Base class for A02 Security Misconfiguration checks.

Every check must be executable independently and return a ScanResult.

Important safety note:
These scripts are designed to *detect* misconfigurations, not to exploit them.
They perform potentially noisy probing ("aggressive"), but keep it bounded with
timeouts, limits, and error handling.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Optional

from .result import ScanResult


@dataclass
class CheckConfig:
    """Runtime tuning knobs (aggressiveness) shared across checks."""

    connect_timeout: float = 3.0
    read_timeout: float = 8.0  # Augmenté pour les tests time-based
    retries: int = 2  # Plus de tentatives
    max_redirects: int = 5
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"  # User-agent plus furtif

    # Runner/Orchestration
    # If a single sub-scan takes too long, the runner can mark it PARTIAL and continue.
    per_scan_timeout_seconds: float = 150.0  # Plus de temps pour les tests offensifs

    # Network scanning aggressiveness (MODE OFFENSIF)
    port_scan_max_ports: int = 65535  # Scan complet
    port_scan_workers: int = 500  # Plus de workers pour scan plus rapide
    banner_read_bytes: int = 4096  # Plus de données pour analyse

    # Web fuzzing aggressiveness (MODE OFFENSIF)
    web_max_paths: int = 800  # Beaucoup plus de chemins
    web_max_requests: int = 1000  # Beaucoup plus de requêtes

    # Injection testing aggressiveness
    sqli_test_payloads: int = 20  # Nombre de payloads SQLi à tester
    xss_test_payloads: int = 15  # Nombre de payloads XSS à tester
    ssrf_test_endpoints: int = 10  # Endpoints SSRF à tester


class BaseCheck(abc.ABC):
    """Abstract base class for all checks."""

    scan_type: str

    def __init__(self, config: Optional[CheckConfig] = None):
        self.config = config or CheckConfig()

    @abc.abstractmethod
    def run(self, target: str) -> ScanResult:
        """Run the check against target and return a ScanResult."""

    def _result(self, target: str) -> ScanResult:
        return ScanResult(scan_type=self.scan_type, target=target)
