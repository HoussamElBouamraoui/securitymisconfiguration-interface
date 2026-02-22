"""Génération d'un rapport PDF InjectionHunter en réutilisant le moteur PDF du
module A02 (Security Misconfiguration).

Principe:
- on transforme d'abord les vulnérabilités InjectionHunter en format agrégé
  compatible avec `a02_security_misconfiguration.reporting.pdf_report`.
- puis on appelle `generate_pdf_report` du module A02.

Ce choix garantit le même rendu PDF (style, tableaux, preuves, etc.).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .a05_aggregator import aggregate_injection_run


def _import_a02_generate_pdf_report():
    """Import robuste du générateur PDF A02.

    Le package `a02_security_misconfiguration` vit sous le dossier
    `Security Misconfiguration/` (avec espace). Selon le répertoire courant,
    ce dossier peut ne pas être dans `sys.path`.
    """

    try:
        from a02_security_misconfiguration.reporting.pdf_report import generate_pdf_report  # type: ignore

        return generate_pdf_report
    except Exception:
        # Fallback: ajouter le dossier parent contenant `a02_security_misconfiguration`.
        import sys
        from pathlib import Path

        repo_root = Path(__file__).resolve().parents[2]
        a02_parent = repo_root / "Security Misconfiguration"
        if a02_parent.exists() and str(a02_parent) not in sys.path:
            sys.path.insert(0, str(a02_parent))

        from a02_security_misconfiguration.reporting.pdf_report import generate_pdf_report  # type: ignore

        return generate_pdf_report


def generate_injection_pdf_report(
    *,
    target: str,
    vulnerabilities: List[Dict[str, Any]],
    output_path: str,
    started_at: Optional[str] = None,
    duration_seconds: Optional[float] = None,
    mode: str = "aggressive",
    project: str = "Pentest Assistant",
    metadata: Optional[Dict[str, Any]] = None,
) -> str:
    """Génère un PDF au style A02 à partir des résultats InjectionHunter."""

    aggregated = aggregate_injection_run(
        target=target,
        vulnerabilities=vulnerabilities,
        started_at=started_at,
        duration_seconds=duration_seconds,
        mode=mode,
        project=project,
        metadata=metadata,
    )

    generate_pdf_report = _import_a02_generate_pdf_report()
    return generate_pdf_report(aggregated, output_path)
