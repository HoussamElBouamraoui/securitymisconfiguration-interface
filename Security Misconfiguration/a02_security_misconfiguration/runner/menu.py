"""Menu console simple pour lancer les scans A02 rapidement.

Usage:
    python -m a02_security_misconfiguration.runner.menu

Objectif:
- lancer un scan complet agressif et produire automatiquement JSON + PDF
- lancer un sous-scan unique
- (option) générer un PDF à partir d'un JSON déjà existant
- (option) sanity-check du JSON pour le reporting

Ce menu reste volontairement simple (pas d'UI), mais il est 'GitHub-ready'.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..core.base_check import CheckConfig
from ..registry import CHECKS


def _prompt(text: str, default: Optional[str] = None) -> str:
    p = f"{text} [{default}]: " if default is not None else f"{text}: "
    v = input(p).strip()
    return v if v else (default or "")


def _prompt_int(text: str, default: int) -> int:
    try:
        return int(_prompt(text, str(default)))
    except ValueError:
        return default


def _prompt_float(text: str, default: float) -> float:
    try:
        return float(_prompt(text, str(default)))
    except ValueError:
        return default


def _artifacts_dir() -> Path:
    p = Path.cwd() / "artifacts"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _print_header() -> None:
    print("\nPentest Assistant — A02 Security Misconfiguration (OWASP Top 10:2025)")
    print("Menu de lancement (console) — best-effort, sans exploitation")
    print("-" * 72)


def _explain_timeouts() -> None:
    print("\nParamètres (rappel):")
    print("- Connect timeout: temps max pour établir la connexion TCP (ex: 3s)")
    print("- Read timeout: temps max pour lire la réponse après connexion (ex: 6s)")
    print("- Retries: nombre de tentatives en cas d'échec (ex: 1)")
    print("- Workers: threads en parallèle (plus = plus rapide, mais plus de charge)")


def _run_full(target: str, connect_timeout: float, read_timeout: float, retries: int, workers: int, out_json: Path, out_pdf: Path) -> int:
    # Import local pour garder le menu léger
    from .run_full_aggressive import main as run_full_main

    argv = [
        "--target",
        target,
        "--connect-timeout",
        str(connect_timeout),
        "--read-timeout",
        str(read_timeout),
        "--retries",
        str(retries),
        "--workers",
        str(workers),
        "--out",
        str(out_json),
        "--pdf",
        str(out_pdf),
    ]
    return int(run_full_main(argv) or 0)


def _run_single(scan_name: str, target: str, cfg: CheckConfig) -> dict:
    cls = CHECKS[scan_name]
    check = cls(cfg)
    r = check.run(target).to_dict()
    return r


def _generate_pdf_from_json(inp_json: Path, out_pdf: Path) -> None:
    from ..reporting.pdf_report import generate_pdf_report

    aggregated = json.loads(inp_json.read_text(encoding="utf-8"))
    generate_pdf_report(aggregated, str(out_pdf))


def _sanity_check_json(inp_json: Path) -> int:
    from .report_sanity_check import main as sanity_main

    return int(sanity_main(["--in", str(inp_json)]) or 0)


def main(argv=None) -> int:
    _print_header()
    _explain_timeouts()

    target = _prompt("Cible (URL ou IP/host)", "http://127.0.0.1")

    connect_timeout = _prompt_float("Connect timeout (s)", 3.0)
    read_timeout = _prompt_float("Read timeout (s)", 6.0)
    retries = max(0, _prompt_int("Retries", 1))

    # Workers: 0 => auto
    workers = _prompt_int("Workers (0=auto)", 0)

    cfg = CheckConfig(connect_timeout=connect_timeout, read_timeout=read_timeout, retries=retries)

    print("\nActions:")
    print("  1) Scan complet agressif (génère JSON + PDF)")
    print("  2) Lancer un sous-scan unique")
    print("  3) Générer un PDF depuis un JSON existant")
    print("  4) Sanity-check d'un JSON (reporting)")
    print("  0) Quitter")

    choice = _prompt_int("Choix", 1)
    if choice == 0:
        return 0

    artifacts = _artifacts_dir()
    ts = _timestamp()

    if choice == 1:
        out_json = artifacts / f"results_{ts}.json"
        out_pdf = artifacts / f"report_{ts}.pdf"
        print(f"\nSorties: {out_json.name} | {out_pdf.name} (dans {artifacts})\n")
        return _run_full(target, connect_timeout, read_timeout, retries, workers, out_json, out_pdf)

    if choice == 2:
        names = sorted(CHECKS.keys())
        print("\nSous-scans disponibles:")
        for i, n in enumerate(names, start=1):
            print(f"  {i:02d}. {n}")

        idx = _prompt_int("Numéro", 1) - 1
        if idx < 0 or idx >= len(names):
            print("Choix invalide.", file=sys.stderr)
            return 2

        scan_name = names[idx]
        out_json = artifacts / f"single_{scan_name}_{ts}.json"

        print(f"\nExécution: {scan_name} -> {out_json.name}\n")
        r = _run_single(scan_name, target, cfg)
        out_json.write_text(json.dumps(r, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(r, indent=2, ensure_ascii=False))
        return 0

    if choice == 3:
        inp = Path(_prompt("Chemin du JSON", str(artifacts / "results.json"))).expanduser()
        if not inp.exists():
            print("Fichier introuvable.", file=sys.stderr)
            return 2

        out_pdf = artifacts / f"report_from_json_{ts}.pdf"
        _generate_pdf_from_json(inp, out_pdf)
        print(f"PDF généré: {out_pdf}")
        return 0

    if choice == 4:
        inp = Path(_prompt("Chemin du JSON", str(artifacts / "results.json"))).expanduser()
        if not inp.exists():
            print("Fichier introuvable.", file=sys.stderr)
            return 2
        return _sanity_check_json(inp)

    print("Choix invalide.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
