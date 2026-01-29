"""Aggressive TCP port scanner (connect scan) for A02 misconfiguration.

Note: A full 1-65535 scan can be slow/noisy. You can tune via CheckConfig.
"""

from __future__ import annotations

from .shared import host_from_target
from ..core.base_check import BaseCheck
from ..core.result import ScanResult
from ..core.utils import port_scan_timeboxed, safe_truncate, select_ports_for_scan


class PortScannerAggressive(BaseCheck):
    scan_type = "A02_Port_Scanner_Aggressive"

    def run(self, target: str) -> ScanResult:
        res = self._result(target)
        host = host_from_target(target)

        # --- Timebox-aware tuning (important for full scan) ---------------------------------
        # En full scan, la config par défaut peut demander 1..65535 ports avec connect_timeout=3s.
        # C'est mathématiquement impossible à terminer en 120s sur la plupart des réseaux.
        # On adapte donc le scope (ports) + on borne les workers pour garantir un retour avant
        # la timebox du runner.
        cfg_max_ports = int(getattr(self.config, "port_scan_max_ports", 65535) or 65535)
        timebox_s = float(getattr(self.config, "per_scan_timeout_seconds", 120.0) or 120.0)
        connect_timeout = float(getattr(self.config, "connect_timeout", 3.0) or 3.0)

        # Borne de workers: trop de threads n'accélère pas forcément (Windows/sockets), et peut
        # empirer la latence. On garde une plage raisonnable.
        cfg_workers = int(getattr(self.config, "port_scan_workers", 200) or 200)
        effective_workers = max(20, min(800, cfg_workers))

        # Budget de ports: estimation conservative (overhead + ports lents). Objectif: finir < timebox.
        # ports/sec ~ workers / (connect_timeout * overhead)
        overhead = 1.8
        est_ports_per_sec = max(1.0, effective_workers / max(0.05, connect_timeout * overhead))
        budget_ports = int(max(200.0, min(float(cfg_max_ports), est_ports_per_sec * max(1.0, timebox_s * 0.85))))

        # Scanne d'abord les ports fréquents, puis le reste jusqu'à budget_ports.
        ports = select_ports_for_scan(budget_ports, prefer_top=True)

        # Expose au rapport pour transparence.
        res.metadata["host"] = host
        res.metadata["max_ports_configured"] = cfg_max_ports
        res.metadata["max_ports_effective"] = budget_ports
        res.metadata["workers_configured"] = cfg_workers
        res.metadata["workers_effective"] = effective_workers
        res.metadata["timebox_seconds"] = timebox_s
        res.metadata["connect_timeout"] = connect_timeout

        if budget_ports < cfg_max_ports:
            res.metadata["note_scope"] = (
                "Scope réduit automatiquement pour respecter la timebox du full scan. "
                "Pour scanner plus de ports, augmentez perScanTimebox et/ou réduisez connectTimeout, "
                "ou exécutez le port scan en single avec une timebox plus grande."
            )

        open_ports, stats = port_scan_timeboxed(
            host,
            ports,
            timeout=connect_timeout,
            workers=effective_workers,
            timebox_seconds=timebox_s,
        )

        res.metadata["open_ports"] = open_ports
        res.metadata["ports_scanned"] = int(stats.get("scanned", 0.0))
        res.metadata["scan_elapsed_seconds"] = float(stats.get("elapsed_seconds", 0.0))
        res.metadata["scan_timeboxed"] = bool(stats.get("timeboxed", 0.0) >= 1.0)

        if res.metadata["scan_timeboxed"]:
            # Le scan a été tronqué par la timebox: on le marque PARTIAL mais on garde les constats.
            res.status = "PARTIAL"
            res.metadata["note"] = (
                "Port scan tronqué (timebox atteinte). Augmentez perScanTimebox/connectTimeout "
                "ou réduisez le scope (max ports/workers) pour une couverture complète."
            )

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

        res.evidence = safe_truncate(
            f"Scanned {res.metadata['ports_scanned']} ports (configured max={cfg_max_ports}, effective max={budget_ports}); "
            f"open: {open_ports}"
        )
        return res
