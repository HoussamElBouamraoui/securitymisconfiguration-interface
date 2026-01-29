"""Run a single A02 misconfiguration sub-scan by name.

Example:
    python -m a02_security_misconfiguration.runner.run_single --target http://example.com --scan http_methods_aggressive
"""

from __future__ import annotations

import argparse
import json
import sys

from ..registry import get_check_by_name
from ..core.base_check import CheckConfig


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Run a single A02 Security Misconfiguration check")
    p.add_argument("--target", required=True, help="URL or host/IP")
    p.add_argument(
        "--scan",
        required=True,
        help="Check name (e.g., http_methods_aggressive, headers_security_check)",
    )
    p.add_argument("--out", help="Optional JSON output file path")
    p.add_argument("--connect-timeout", type=float, default=3.0)
    p.add_argument("--read-timeout", type=float, default=6.0)
    p.add_argument("--retries", type=int, default=1)
    # Compat API: le runner full accepte --per-scan-timebox. Pour les sous-scans,
    # on l'accepte aussi pour éviter une erreur d'arguments (même si le check
    # n'applique pas forcément une timebox stricte).
    p.add_argument("--per-scan-timebox", type=float, default=120.0)
    args = p.parse_args(argv)

    cfg = CheckConfig(
        connect_timeout=args.connect_timeout,
        read_timeout=args.read_timeout,
        retries=max(0, args.retries),
    )

    # "Single scan" safety: éviter un port scan complet (65535) qui peut durer longtemps.
    # On approxime un budget via per-scan-timebox en réduisant les ports max et les workers.
    # But: rendre la commande `scanmod port_scanner_aggressive ...` utilisable en local.
    try:
        timebox = float(args.per_scan_timebox)
    except Exception:
        timebox = 120.0

    # Heuristique: ~1000 ports par seconde de budget (très approximatif, dépend du réseau).
    # On borne pour rester raisonnable.
    cfg.per_scan_timeout_seconds = max(10.0, timebox)
    budget_ports = int(max(0.0, timebox) * 100)
    cfg.port_scan_max_ports = max(256, min(5000, budget_ports))
    cfg.port_scan_workers = int(max(50, min(300, cfg.port_scan_workers)))

    cls = get_check_by_name(args.scan)
    if cls is None:
        print(f"Unknown scan: {args.scan}", file=sys.stderr)
        print("Available scans:")
        for n in sorted(get_check_by_name("__list__") or []):
            print(f" - {n}")
        return 2

    check = cls(cfg)
    result = check.run(args.target)
    payload = result.to_dict()
    if args.out:
        try:
            with open(args.out, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Failed to write --out file: {type(e).__name__}: {e}", file=sys.stderr)
            return 2

    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
