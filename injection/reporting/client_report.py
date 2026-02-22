#!/usr/bin/env python3
"""
Rapport PDF InjectionHunter — style client, lecture facile.
Utilise le logo injection/image/logoinjection.png et une mise en page professionnelle.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Image as RLImage,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Palette lisible pour le client
_PALETTE = {
    "text": colors.HexColor("#1a1a2e"),
    "muted": colors.HexColor("#6c757d"),
    "line": colors.HexColor("#dee2e6"),
    "header": colors.HexColor("#16213e"),
    "accent": colors.HexColor("#0f3460"),
    "card_bg": colors.HexColor("#f8f9fa"),
    "critical": colors.HexColor("#721c24"),
    "high": colors.HexColor("#c0392b"),
    "medium": colors.HexColor("#d68910"),
    "low": colors.HexColor("#1e8449"),
    "info": colors.HexColor("#2874a6"),
}

_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_SEV_COLORS = {
    "INFO": _PALETTE["info"],
    "LOW": _PALETTE["low"],
    "MEDIUM": _PALETTE["medium"],
    "HIGH": _PALETTE["high"],
    "CRITICAL": _PALETTE["critical"],
}


def _norm_sev(s: Any) -> str:
    v = str(s or "INFO").upper().strip()
    return v if v in _SEV_ORDER else "INFO"


def _escape(t: str) -> str:
    return (t or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")


def _sev_color(sev: str):
    return _SEV_COLORS.get(_norm_sev(sev), _PALETTE["accent"])


def _resolve_logo_path(logo_path: Optional[str] = None) -> Optional[str]:
    """Retourne le chemin absolu du logo Injection."""
    if logo_path and os.path.isfile(logo_path):
        return os.path.abspath(logo_path)
    # Défaut: injection/image/logoinjection.png depuis ce package
    base = Path(__file__).resolve().parents[1]
    default = base / "image" / "logoinjection.png"
    if default.exists():
        return str(default)
    return None


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="ClientTitle",
            fontName="Helvetica-Bold",
            fontSize=18,
            textColor=_PALETTE["header"],
            spaceAfter=12,
            alignment=1,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ClientHeading2",
            fontName="Helvetica-Bold",
            fontSize=14,
            textColor=_PALETTE["accent"],
            spaceBefore=14,
            spaceAfter=8,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ClientBody",
            fontName="Helvetica",
            fontSize=10,
            textColor=_PALETTE["text"],
            spaceAfter=6,
            leading=13,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ClientEvidence",
            fontName="Courier",
            fontSize=9,
            textColor=_PALETTE["text"],
            backColor=_PALETTE["card_bg"],
            borderPadding=8,
            spaceAfter=6,
            leading=11,
        )
    )
    styles.add(
        ParagraphStyle(
            name="ClientMuted",
            fontName="Helvetica",
            fontSize=9,
            textColor=_PALETTE["muted"],
            spaceAfter=4,
        )
    )
    return styles


def build_flow(aggregated: Dict[str, Any], logo_path: Optional[str] = None):
    """Construit la liste des flowables pour le PDF."""
    styles = _build_styles()
    target = aggregated.get("target", "N/A")
    project = aggregated.get("project", "Pentest Assistant")
    mode = aggregated.get("mode", "standard")
    meta = aggregated.get("metadata") or {}
    brand = meta.get("brand") or {}
    logo_path = logo_path or brand.get("logo_path")
    date_str = aggregated.get("started_at") or datetime.now().strftime("%Y-%m-%d %H:%M")

    flow = []

    # Cover
    logo_file = _resolve_logo_path(logo_path)
    if logo_file:
        try:
            img = RLImage(logo_file, width=4 * cm, height=4 * cm)
            img.hAlign = "CENTER"
            flow.extend([Spacer(1, 2 * cm), img, Spacer(1, 0.8 * cm)])
        except Exception:
            pass
    flow.extend([
        Paragraph("RAPPORT PENTEST — INJECTION", styles["ClientTitle"]),
        Paragraph("OWASP Top 10 A05:2025 — Assistant d'exploitation", styles["ClientHeading2"]),
        Spacer(1, 0.5 * cm),
        Paragraph(f"<b>Cible:</b> {_escape(target)}", styles["ClientBody"]),
        Paragraph(f"<b>Projet:</b> {_escape(project)}", styles["ClientBody"]),
        Paragraph(f"<b>Mode:</b> {_escape(mode)}", styles["ClientBody"]),
        Paragraph(f"<b>Date:</b> {_escape(date_str)}", styles["ClientBody"]),
        Spacer(1, 1.5 * cm),
        Paragraph(
            "Rapport d'assistant de pentest : pour chaque vulnérabilité sont fournis une description technique, "
            "un guide d'exploitation (étapes, commandes, outils) et la preuve du scan. Utilisation strictement en contexte autorisé.",
            styles["ClientMuted"],
        ),
        Spacer(1, 2 * cm),
    ])

    # Summary
    summary = aggregated.get("summary") or {}
    total = summary.get("total_findings", 0)
    by_sev = summary.get("findings_by_severity") or {}
    overall = summary.get("overall_severity", "INFO")
    data = [
        ["Synthèse", ""],
        ["Nombre total de findings", str(total)],
        ["Sévérité maximale", overall],
        ["CRITICAL", str(by_sev.get("CRITICAL", 0))],
        ["HIGH", str(by_sev.get("HIGH", 0))],
        ["MEDIUM", str(by_sev.get("MEDIUM", 0))],
        ["LOW", str(by_sev.get("LOW", 0))],
        ["INFO", str(by_sev.get("INFO", 0))],
    ]
    t = Table(data, colWidths=[6 * cm, 6 * cm])
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), _PALETTE["accent"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, _PALETTE["line"]),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("BACKGROUND", (0, 1), (-1, -1), _PALETTE["card_bg"]),
        ])
    )
    flow.extend([
        PageBreak(),
        Paragraph("1. Synthèse", styles["ClientTitle"]),
        Spacer(1, 0.3 * cm),
        t,
        Spacer(1, 1 * cm),
        Paragraph("2. Vulnérabilités — Description, exploitation et preuve", styles["ClientTitle"]),
        Spacer(1, 0.5 * cm),
    ])

    # Findings
    results = aggregated.get("results") or []
    for idx, scan in enumerate(results, 1):
        scan_type = scan.get("scan_type", "unknown")
        findings = scan.get("findings") or []
        if not findings:
            continue
        flow.append(Paragraph(f"2.{idx} — {_escape(scan_type)} ({len(findings)} finding(s))", styles["ClientHeading2"]))

        for i, f in enumerate(findings, 1):
            title = f.get("title", "Sans titre")
            severity = _norm_sev(f.get("severity"))
            explanation = (f.get("explanation") or "").strip()
            exploitation = (f.get("exploitation") or "").strip()
            recommendation = f.get("recommendation", "")
            evidence = (f.get("evidence") or "").strip()
            cwe = f.get("cwe", "")

            badge = Table([[_escape(severity)]], colWidths=[2 * cm])
            badge.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), _sev_color(severity)),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ])
            )
            block = [
                Paragraph(f"<b>Finding {i}:</b> {_escape(title)}", styles["ClientBody"]),
                badge,
                Spacer(1, 0.2 * cm),
            ]
            if cwe:
                block.append(Paragraph(f"<b>CWE:</b> {_escape(cwe)}", styles["ClientMuted"]))
            if explanation:
                expl_esc = _escape(explanation)
                if len(expl_esc) > 800:
                    expl_esc = expl_esc[:800] + "…"
                block.append(Paragraph(f"<b>Description (vulnérabilité):</b><br/>{expl_esc}", styles["ClientBody"]))
            if exploitation:
                exploi_esc = _escape(exploitation)
                if len(exploi_esc) > 1500:
                    exploi_esc = exploi_esc[:1500] + "…"
                block.append(Paragraph(f"<b>Comment exploiter:</b><br/><font face='Courier' size='8'>{exploi_esc}</font>", styles["ClientEvidence"]))
            if evidence:
                evidence_esc = _escape(evidence)
                if len(evidence_esc) > 800:
                    evidence_esc = evidence_esc[:800] + "..."
                block.append(Paragraph(f"<b>Preuve (requête / réponse):</b><br/><font face='Courier' size='8'>{evidence_esc}</font>", styles["ClientEvidence"]))
            if recommendation:
                rec_esc = _escape(recommendation[:500])
                if len(recommendation) > 500:
                    rec_esc += "…"
                block.append(Paragraph(f"<b>Remédiation (pour le client):</b><br/>{rec_esc}", styles["ClientBody"]))
            block.append(Spacer(1, 0.5 * cm))

            inner = Table([[b] for b in block], colWidths=[16 * cm])
            inner.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), _PALETTE["card_bg"]),
                    ("BOX", (0, 0), (-1, -1), 0.8, _PALETTE["line"]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 12),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ])
            )
            flow.append(inner)

        flow.append(Spacer(1, 0.5 * cm))

    flow.extend([Spacer(1, 1 * cm), Paragraph("— Fin du rapport —", styles["ClientMuted"])])
    return flow


def generate_client_pdf(aggregated: Dict[str, Any], output_path: str, *, logo_path: Optional[str] = None) -> str:
    """Génère le PDF client. Utilise le logo injection/image/logoinjection.png par défaut."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=1.5 * cm,
        leftMargin=1.5 * cm,
        topMargin=1.2 * cm,
        bottomMargin=1.2 * cm,
    )
    flow = build_flow(aggregated, logo_path=logo_path)
    doc.build(flow)
    return output_path
