"""CLI pour générer un rapport PDF InjectionHunter.

Usage:
  python -m injection.reporting.cli --in results.json --out report.pdf
  python -m injection.reporting.cli --in results.json --out report.pdf --style client

- `--style client` : rapport style client (logo Injection, lecture facile).
- `--in` : JSON avec clé `vulnerabilities` ou liste de vulns.
- `--target` optionnel : sinon pris dans le JSON.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from .a05_aggregator import aggregate_injection_run


def _load_input(path: Path) -> Tuple[str, List[Dict[str, Any]]]:
    raw = json.loads(path.read_text(encoding="utf-8"))

    target = ""
    vulns: List[Dict[str, Any]] = []

    if isinstance(raw, list):
        vulns = raw
    elif isinstance(raw, dict):
        target = str(raw.get("target") or raw.get("url") or "")
        if isinstance(raw.get("vulnerabilities"), list):
            vulns = raw["vulnerabilities"]
        elif isinstance(raw.get("results"), list):
            for r in raw.get("results") or []:
                vulns.extend(r.get("findings") or r.get("vulnerabilities") or [])
    else:
        raise ValueError("Format JSON non supporté (attendu: list ou dict)")

    return target, vulns


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Générer un rapport PDF InjectionHunter")
    ap.add_argument("--in", dest="inp", required=True, help="Chemin JSON (liste ou dict avec vulnerabilities)")
    ap.add_argument("--out", required=True, help="Chemin du PDF")
    ap.add_argument("--target", help="Cible (override)")
    ap.add_argument("--project", default="Pentest Assistant", help="Nom du projet")
    ap.add_argument("--mode", default="aggressive", help="Mode affiché dans le PDF")
    ap.add_argument("--style", choices=("client", "a02"), default="client",
                    help="Style du rapport: client (logo Injection, lisible) ou a02 (compat A02)")
    args = ap.parse_args(argv)

    inp = Path(args.inp)
    if not inp.exists():
        raise SystemExit(f"Fichier introuvable: {inp}")

    target_from_json, vulns = _load_input(inp)
    target = args.target or target_from_json
    if not target:
        raise SystemExit("Target manquant. Fournis --target ou ajoute `target` dans le JSON.")

    t0 = time.time()
    aggregated = aggregate_injection_run(
        target=target,
        vulnerabilities=vulns,
        duration_seconds=0,
        mode=args.mode,
        project=args.project,
        metadata={"source_json": str(inp)},
    )
    aggregated["duration_seconds"] = round(time.time() - t0, 3)

    if args.style == "client":
        from .client_report import generate_client_pdf
        logo_path = str(Path(__file__).resolve().parents[1] / "image" / "logoinjection.png")
        generate_client_pdf(aggregated, args.out, logo_path=logo_path)
    else:
        from .pdf_report import generate_injection_pdf_report
        generate_injection_pdf_report(
            target=target,
            vulnerabilities=vulns,
            output_path=args.out,
            duration_seconds=aggregated["duration_seconds"],
            mode=args.mode,
            project=args.project,
            metadata={"source_json": str(inp)},
        )

    print(f"PDF généré: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
