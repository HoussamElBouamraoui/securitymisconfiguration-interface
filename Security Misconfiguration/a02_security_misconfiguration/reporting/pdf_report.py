"""PDF report generator for A02 Security Misconfiguration.

Important: This module is decoupled from the scanning engine.
It only consumes the aggregated result dict produced by the runner.

Audit-ready UX goals:
- Word-wrap everywhere in tables. Never truncate with "...".
- Dense, content-driven layout: avoid large blank zones.
- No raw Python stack traces in user-facing report.
- Consistent table styling across the entire document.

Dependencies: reportlab
"""

from __future__ import annotations

from typing import Any, Dict, List

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.platypus import Image as RLImage

import re
import html


# ---------------- Visual tokens ----------------
_PALETTE = {
    "text": colors.HexColor("#111827"),
    "muted": colors.HexColor("#6B7280"),
    "line": colors.HexColor("#E5E7EB"),
    "header": colors.HexColor("#0F172A"),
    "accent": colors.HexColor("#1F5FBF"),
    "card_bg": colors.HexColor("#F9FAFB"),
    "dark_box": colors.HexColor("#111827"),
    "thead": colors.HexColor("#111827"),
}

_SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
_CONF_ORDER = ["low", "medium", "high"]

_SEV_COLORS = {
    "INFO": colors.HexColor("#2E7D32"),
    "LOW": colors.HexColor("#F2C94C"),
    "MEDIUM": colors.HexColor("#F2994A"),
    "HIGH": colors.HexColor("#EB5757"),
    "CRITICAL": colors.HexColor("#7A0000"),
}

_SEV_ICON = {"INFO": "i", "LOW": "!", "MEDIUM": "!!", "HIGH": "!!!", "CRITICAL": "!!!!"}


def _escape(text: str) -> str:
    return (
        (text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )


def _norm_sev(value: str) -> str:
    v = str(value or "INFO").upper().strip()
    return v if v in _SEV_ORDER else "INFO"


def _norm_conf(value: str) -> str:
    v = str(value or "low").lower().strip()
    return v if v in _CONF_ORDER else "low"


def _sev_color(sev: str):
    return _SEV_COLORS.get(_norm_sev(sev), _PALETTE["accent"])


def _badge(label: str, sev: str | None = None, *, bg: colors.Color | None = None) -> Table:
    color = bg if bg is not None else _sev_color(sev or "INFO")
    t = Table([[label]], colWidths=[None])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    return t


def _card(flowables: List[Any], *, accent: colors.Color | None = None, width: float = 17.2 * cm) -> Table:
    rows = [[f] for f in flowables]
    t = Table(rows, colWidths=[width])
    style = [
        ("BACKGROUND", (0, 0), (-1, -1), _PALETTE["card_bg"]),
        ("BOX", (0, 0), (-1, -1), 0.6, _PALETTE["line"]),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]
    if accent is not None:
        style.append(("LINEABOVE", (0, 0), (-1, 0), 2.0, accent))
    t.setStyle(TableStyle(style))
    return t


# Limite de sécurité pour éviter les LayoutError sur pages très chargées
_MAX_EVIDENCE_LINES_PER_BOX = 15  # Réduit de 28 à 15 pour éviter LayoutError sur Windows
_MAX_FINDING_FIELDS_LINES = 12    # Réduit aussi pour cohérence


def _cap_evidence_lines(text: str, max_lines: int = _MAX_EVIDENCE_LINES_PER_BOX) -> Dict[str, Any]:
    lines = (text or "").splitlines()
    total = len(lines)
    if total <= max_lines:
        return {"text": "\n".join(lines), "truncated": False, "total": total, "shown": total}
    return {"text": "\n".join(lines[:max_lines]), "truncated": True, "total": total, "shown": max_lines}


def _standard_table(data: List[List[Any]], col_widths: List[float], *, header_dark: bool = True, repeat_header: bool = True) -> Table:
    """One unified table style for the whole report.

    Notes UX:
    - We only repeat header rows for real multi-row tables.
      Repeating a header on a 1-row table can cause layout glitches.
    - splitByRow=1 permet à ReportLab de découper une table sur plusieurs pages,
      ce qui évite des LayoutError quand une cellule devient très haute.
    """

    t = Table(
        data,
        colWidths=col_widths,
        repeatRows=1 if (repeat_header and len(data) > 1) else 0,
        splitByRow=1,
    )

    style = [
        ("GRID", (0, 0), (-1, -1), 0.6, _PALETTE["line"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#FAFAFA")]),
    ]

    if header_dark:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), _PALETTE["thead"]),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ]

    t.setStyle(TableStyle(style))
    return t


def _strip_to_one_line(s: str) -> str:
    return (s or "").replace("\r", "").split("\n", 1)[0].strip()


def _make_error_box(scan: Dict[str, Any], styles: Dict[str, ParagraphStyle]) -> Table:
    """User-facing error box (no stack trace)."""

    md = scan.get("metadata", {}) or {}
    cause = md.get("error_cause") or "Erreur interne"
    rec = md.get("error_recommendation") or "Relancer avec des timeouts plus élevés et vérifier la connectivité."

    return _card(
        [
            _p("Scan partiellement exécuté — une erreur technique interne a limité la couverture de ce test. Les autres résultats restent valides.", styles["body"]),
            _p(f"Cause: {cause}", styles["body"]),
            _p(f"Action recommandée: {rec}", styles["body"]),
        ],
        accent=_sev_color("LOW"),
    )


def _make_findings_table(findings: List[Dict[str, Any]], styles: Dict[str, ParagraphStyle]) -> Table:
    """Findings table with robust wrapping and readable column widths.

    Important: certains targets renvoient des preuves très longues dans risk/recommendation.
    On tronque ces champs dans la table pour éviter des cellules gigantesques qui cassent le layout.
    Les preuves complètes restent disponibles dans la section "PREUVES TECHNIQUES".
    """

    def _truncate_paragraph(s: Any, *, max_lines: int) -> str:
        txt = _sanitize_text(s)
        if not txt:
            return ""
        lines = txt.splitlines()
        if len(lines) <= max_lines:
            return txt
        return "\n".join(lines[:max_lines]) + f"\n[...] (tronqué, {len(lines)} lignes)"

    data: List[List[Any]] = [[
        _p("ID", styles["cell_bold"]),
        _p("Problème", styles["cell_bold"]),
        _p("Sévérité", styles["cell_bold"]),
        _p("Pourquoi c’est dangereux", styles["cell_bold"]),
        _p("Action immédiate", styles["cell_bold"]),
    ]]

    for idx, f in enumerate(findings, start=1):
        fsev = _norm_sev(f.get("severity"))
        data.append(
            [
                _p(f"F{idx}", styles["cell_small"]),
                _p(_truncate_paragraph(f.get("title", ""), max_lines=3), styles["cell_small"]),
                _badge(f"{_SEV_ICON.get(fsev,'!')} {fsev}", fsev),
                _p(_truncate_paragraph(f.get("risk", ""), max_lines=_MAX_FINDING_FIELDS_LINES), styles["cell_small"]),
                _p(_truncate_paragraph(f.get("recommendation", ""), max_lines=_MAX_FINDING_FIELDS_LINES), styles["cell_small"]),
            ]
        )

    col_widths = [1.0 * cm, 4.6 * cm, 2.1 * cm, 4.9 * cm, 4.6 * cm]
    return _standard_table(data, col_widths, header_dark=True, repeat_header=True)


def _collect_top_actions(results: List[Dict[str, Any]], limit: int = 3) -> List[Dict[str, str]]:
    """Top actions from findings (decision-oriented)."""

    flat: List[Dict[str, Any]] = []
    for r in results:
        if str(r.get("status", "COMPLETED")).upper() == "ERROR":
            continue
        for f in r.get("findings", []) or []:
            flat.append({**f, "_scan_type": r.get("scan_type", "")})

    flat.sort(
        key=lambda f: (
            -_SEV_ORDER.index(_norm_sev(f.get("severity"))),
            -_CONF_ORDER.index(_norm_conf(f.get("confidence"))),
            str(f.get("title", "")),
        )
    )

    out: List[Dict[str, str]] = []
    for f in flat:
        if len(out) >= limit:
            break
        out.append(
            {
                "title": _strip_to_one_line(str(f.get("title", ""))),
                "severity": _norm_sev(f.get("severity")),
                "action": _strip_to_one_line(str(f.get("recommendation", ""))),
                "why": _strip_to_one_line(str(f.get("risk", ""))),
                "scan": _strip_to_one_line(str(f.get("_scan_type", ""))),
            }
        )
    return out


def _risk_gauge(level: str, width: float = 17.2 * cm, height: float = 1.15 * cm) -> Drawing:
    lvl = _norm_sev(level)
    labels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    step_w = width / 5.0

    d = Drawing(width, height)
    for i, s in enumerate(labels):
        d.add(Rect(i * step_w, 0, step_w, height, fillColor=_sev_color(s), strokeColor=colors.white, strokeWidth=1))
        d.add(String(i * step_w + 2, height - 10, s, fontName="Helvetica-Bold", fontSize=7, fillColor=colors.white))

    idx = labels.index(lvl)
    marker_x = idx * step_w + step_w / 2
    d.add(Rect(marker_x - 2, 0, 4, height, fillColor=colors.black, strokeColor=colors.black, strokeWidth=0))
    return d


def _normalize_sev_counts(d: Dict[str, Any]) -> Dict[str, int]:
    out = {k: 0 for k in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    for k, v in (d or {}).items():
        kk = str(k).upper()
        if kk in out:
            out[kk] = int(v)
    return out


def _chart_findings_by_severity(counts: Dict[str, int], width: float = 17.2 * cm, height: float = 4.8 * cm) -> Drawing:
    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    values = [counts.get(k, 0) for k in labels]

    d = Drawing(width, height)
    bc = VerticalBarChart()
    bc.x = 0.8 * cm
    bc.y = 0.8 * cm
    bc.height = height - 1.5 * cm
    bc.width = width - 1.6 * cm
    bc.data = [values]
    bc.valueAxis.valueMin = 0
    bc.valueAxis.valueMax = max(values + [1])
    bc.valueAxis.valueStep = max(1, int(bc.valueAxis.valueMax / 4) or 1)
    bc.categoryAxis.categoryNames = labels
    bc.barWidth = 0.55 * cm

    for i, sev in enumerate(labels):
        bc.bars[(0, i)].fillColor = _sev_color(sev)

    d.add(bc)
    d.add(String(0.8 * cm, height - 0.35 * cm, "Findings par sévérité", fontName="Helvetica-Bold", fontSize=10, fillColor=_PALETTE["text"]))
    return d


def _chart_scans_by_type(results: List[Dict[str, Any]], width: float = 17.2 * cm, height: float = 4.8 * cm) -> Drawing:
    buckets = {"Network": 0, "Web": 0, "Other": 0}
    for r in results:
        st = (r.get("scan_type") or "").lower()
        if "a02_" not in st:
            buckets["Other"] += 1
        elif any(k in st for k in ["port_", "smb", "ftp", "banner", "service", "network", "open_services", "default_services"]):
            buckets["Network"] += 1
        else:
            buckets["Web"] += 1

    labels = ["Network", "Web", "Other"]
    values = [buckets[k] for k in labels]
    if sum(values) == 0:
        values = [1, 0, 0]

    d = Drawing(width, height)
    pie = Pie()
    pie.x = 0.8 * cm
    pie.y = 0.2 * cm
    pie.width = min(10.0 * cm, width - 1.6 * cm)
    pie.height = height - 0.8 * cm
    pie.data = values
    pie.labels = labels

    colors_map = {"Network": colors.HexColor("#1F5FBF"), "Web": colors.HexColor("#2E7D32"), "Other": colors.HexColor("#6B7280")}
    for i, lab in enumerate(labels):
        pie.slices[i].fillColor = colors_map[lab]
        pie.slices[i].strokeColor = colors.white
        pie.slices[i].strokeWidth = 0.3

    d.add(pie)
    d.add(String(0.8 * cm, height - 0.35 * cm, "Répartition par type de scan", fontName="Helvetica-Bold", fontSize=10, fillColor=_PALETTE["text"]))
    return d


def _fit_image(path: str, *, max_w: float, max_h: float, h_align: str = "CENTER") -> RLImage:
    """Load an image and scale it to fit inside (max_w, max_h) while preserving aspect ratio."""
    img = RLImage(path)
    try:
        iw = float(img.imageWidth)
        ih = float(img.imageHeight)
    except Exception:
        iw, ih = 1.0, 1.0

    scale = min(max_w / iw, max_h / ih)
    img.drawWidth = iw * scale
    img.drawHeight = ih * scale
    img.width = img.drawWidth
    img.height = img.drawHeight
    img.hAlign = h_align
    return img


def _cover_page(
    *,
    styles: Dict[str, ParagraphStyle],
    project: str,
    target: str,
    started_at: str,
    mode: str,
    score_level: str,
    score_conf: str,
    total_scans: int,
    total_findings: int,
) -> List[Any]:
    """Page de garde académique stylée.

    Remplissage utile (pas de grand blanc):
    - Logo centré
    - Titre
    - Cartouche "Objectif du rapport" + "Périmètre & limites" (non technique)
    """

    from pathlib import Path

    flow: List[Any] = []

    logo_path = Path(__file__).resolve().parents[1] / "image" / "logo_security_misconfiguration.png"
    if logo_path.exists():
        img = _fit_image(str(logo_path), max_w=14.5 * cm, max_h=5.6 * cm, h_align="CENTER")
        flow.append(Spacer(1, 10))
        flow.append(img)
        flow.append(Spacer(1, 10))

    title_style = ParagraphStyle(
        "CoverTitle",
        parent=styles["h1"],
        alignment=1,
        fontSize=18,
        leading=22,
        spaceAfter=6,
    )
    subtitle_style = ParagraphStyle(
        "CoverSubtitle",
        parent=styles["body"],
        alignment=1,
        fontSize=12,
        leading=16,
        textColor=_PALETTE["muted"],
        spaceAfter=10,
    )

    flow.append(Paragraph("Audit de sécurité – OWASP Top 10:2025", title_style))
    flow.append(Paragraph("A02 – Security Misconfiguration", ParagraphStyle("CoverH2", parent=subtitle_style, fontSize=14, leading=18, textColor=_PALETTE["header"])) )
    flow.append(Paragraph("Rapport de scan automatisé (best-effort)", subtitle_style))

    # Big KPI ribbon (non-tech) to fill the page
    ribbon = _standard_table(
        [[
            Paragraph(f"<b>Projet</b><br/>{_escape(project or 'Pentest Assistant')}", styles["body"]),
            Paragraph(f"<b>Date</b><br/>{_escape(str(started_at))}", styles["body"]),
            Paragraph(f"<b>Mode</b><br/>{_escape(str(mode))}", styles["body"]),
            Paragraph(f"<b>Risque global</b><br/>{_escape(score_level)} ({_escape(score_conf)})", styles["body"]),
        ]],
        [4.3 * cm, 4.3 * cm, 4.3 * cm, 4.3 * cm],
        header_dark=False,
        repeat_header=False,
    )
    flow.append(Spacer(1, 10))
    flow.append(ribbon)

    # Objective + scope/limits (useful content that removes whitespace)
    flow.append(Spacer(1, 10))
    flow.append(
        _card(
            [
                Paragraph("<b>Objectif du rapport</b>", styles["body"]),
                Paragraph(
                    _escape(
                        "Fournir une synthèse claire des risques de configuration (A02) détectés automatiquement, "
                        "afin d’aider à prioriser les corrections et préparer une validation manuelle."
                    ),
                    styles["body"],
                ),
                Spacer(1, 6),
                Paragraph("<b>Périmètre & limites</b>", styles["body"]),
                Paragraph(
                    _escape(
                        "Analyse automatisée best-effort (sans exploitation). Les résultats peuvent contenir des faux positifs/negatifs. "
                        "Une validation manuelle est recommandée, surtout pour les points HIGH/CRITICAL."
                    ),
                    styles["body"],
                ),
            ],
            accent=_PALETTE["accent"],
        )
    )

    # Footer
    flow.append(Spacer(1, 18))
    flow.append(Paragraph(_escape("Pentest Assistant – Rapport de scan de sécurité"), ParagraphStyle("CoverFoot", parent=styles["muted"], alignment=1)))

    return flow


# Characters to strip from user-visible PDF output
_STRIP_CHARS = {
    "\u200b",  # zero width space
    "\ufeff",  # BOM
    "\u00a0",  # nbsp
}


def _sanitize_text(s: Any) -> str:
    """Sanitize any text going into Paragraph.

    Goals:
    - remove invisible chars that leak as entities (ZWSP, nbsp)
    - unescape HTML entities that might have been introduced
    - keep it safe for ReportLab Paragraph (escape <, >, &)
    """

    if s is None:
        return ""
    txt = str(s)

    # Decode any HTML entities (e.g. &#8203;) coming from previous versions
    try:
        txt = html.unescape(txt)
    except Exception:
        pass

    # Strip problematic invisible chars
    for ch in _STRIP_CHARS:
        txt = txt.replace(ch, "")

    # Normalize newlines (Paragraph uses <br/>)
    txt = txt.replace("\r\n", "\n").replace("\r", "\n")

    return txt


def _p(text: Any, style: ParagraphStyle) -> Paragraph:
    """Shortcut: sanitize + escape + Paragraph."""
    return Paragraph(_escape(_sanitize_text(text)), style)


def _soft_wrap_identifier(text: str) -> str:
    """Rendre un identifiant (scan_type) cassable proprement.

    Important UX:
    - pas d'entités HTML (ex: &#8203;) qui peuvent fuiter
    - pas de ZWSP (\u200b) conservés dans le PDF

    Stratégie: insérer des espaces autour de séparateurs sûrs, puis normaliser.
    ReportLab casse naturellement sur les espaces.
    """

    s = _sanitize_text(text).strip()
    if not s:
        return ""

    # Break opportunities on underscores and camelCase transitions.
    # We keep the original identifier readable & printable.
    s = s.replace("_", " _ ")
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", s)
    s = re.sub(r"([A-Za-z])([0-9])", r"\1 \2", s)
    s = re.sub(r"([0-9])([A-Za-z])", r"\1 \2", s)

    # Collapse repeated whitespace
    s = re.sub(r"\s+", " ", s).strip()
    return s


def _humanize_scan_type(scan_type: str) -> str:
    """Version plus lisible pour utilisateurs non tech.

    Exemple:
      A02_HTTP_Methods_Aggressive -> A02 – HTTP Methods (Aggressive)
    """

    raw = _sanitize_text(scan_type).strip()
    if not raw:
        return "Sous-scan"

    parts = raw.split("_")
    if len(parts) <= 1:
        return raw

    prefix = parts[0]
    rest = parts[1:]

    # Format words
    nice_words: List[str] = []
    for w in rest:
        if not w:
            continue
        if w.isupper() or w.isdigit():
            nice_words.append(w)
        else:
            # split CamelCase to words
            w2 = re.sub(r"([a-z])([A-Z])", r"\1 \2", w)
            nice_words.append(w2)

    # Put Aggressive/Common postfix in parentheses when it exists
    if nice_words and nice_words[-1].lower() in {"aggressive", "passive", "check", "detection", "analysis", "probing"}:
        postfix = nice_words.pop(-1)
        label = " ".join(nice_words).strip() or raw
        return f"{prefix} – {label} ({postfix.capitalize()})"

    return f"{prefix} – {' '.join(nice_words).strip()}"


# --- Evidence box (robuste) ---

def _evidence_box(text: str, styles: Dict[str, ParagraphStyle]) -> Table:
    capped = _cap_evidence_lines(_sanitize_text(text), max_lines=_MAX_EVIDENCE_LINES_PER_BOX)
    header = "PREUVES TECHNIQUES (extrait)"
    if capped["truncated"]:
        header += f" — tronquées ({capped['shown']}/{capped['total']} lignes)"

    p_header = _p(header, styles["muted_white"])
    p = Paragraph(_escape(_sanitize_text(capped["text"] or "")), styles["code_dark"])

    t = Table([[p_header], [p]], colWidths=[16.6 * cm], splitByRow=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), _PALETTE["dark_box"]),
                ("BOX", (0, 0), (-1, -1), 0.6, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), 10),
                ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return t


def generate_pdf_report(aggregated: Dict[str, Any], output_path: str) -> str:
    base = getSampleStyleSheet()

    styles = {
        "h1": ParagraphStyle("H1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=14, textColor=_PALETTE["header"], spaceAfter=6),
        "h2": ParagraphStyle("H2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=11, textColor=_PALETTE["header"], spaceAfter=4),
        "body": ParagraphStyle("B", parent=base["BodyText"], fontName="Helvetica", fontSize=9.5, leading=12, textColor=_PALETTE["text"], splitLongWords=0),
        "muted": ParagraphStyle("M", parent=base["BodyText"], fontName="Helvetica", fontSize=8.7, leading=11, textColor=_PALETTE["muted"], splitLongWords=0),
        "muted_white": ParagraphStyle("MW", parent=base["BodyText"], fontName="Helvetica", fontSize=8.7, leading=11, textColor=colors.HexColor("#E5E7EB"), splitLongWords=0),
        "cell": ParagraphStyle("Cell", parent=base["BodyText"], fontName="Helvetica", fontSize=9, leading=11, textColor=_PALETTE["text"], wordWrap="LTR", splitLongWords=0),
        "cell_bold": ParagraphStyle("CellB", parent=base["BodyText"], fontName="Helvetica-Bold", fontSize=9, leading=11, textColor=_PALETTE["text"], wordWrap="LTR", splitLongWords=0),
        "cell_small": ParagraphStyle("CellS", parent=base["BodyText"], fontName="Helvetica", fontSize=8.6, leading=10.8, textColor=_PALETTE["text"], wordWrap="LTR", splitLongWords=0),
        "code_dark": ParagraphStyle("CD", parent=base["BodyText"], fontName="Courier", fontSize=7.6, leading=9.5, textColor=colors.HexColor("#E5E7EB")),
    }

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=1.6 * cm,
        rightMargin=1.6 * cm,
        topMargin=1.4 * cm,
        bottomMargin=1.4 * cm,
        title="A02 – Security Misconfiguration Scan Report",
        author=str(aggregated.get("project", "Pentest Assistant")),
    )

    summary = aggregated.get("summary", {})
    results = sorted((aggregated.get("results", []) or []), key=lambda r: r.get("scan_type", ""))

    target = aggregated.get("target", "")
    started_at = aggregated.get("started_at") or "N/A"
    mode = aggregated.get("mode", "aggressive")
    project = aggregated.get("project", "Pentest Assistant")

    score = summary.get("a02_risk_score", {}) or {}
    score_level = _norm_sev(score.get("level", summary.get("overall_severity", "INFO")))
    score_conf = _norm_conf(score.get("confidence", summary.get("overall_confidence", "low")))

    total_scans = int(summary.get("total_scans", len(results)) or 0)
    total_findings = int(summary.get("total_findings", 0) or 0)

    story: List[Any] = []

    # --- NEW Page 1: Cover page (stylée + logo) ---
    story.extend(
        _cover_page(
            styles=styles,
            project=project,
            target=target,
            started_at=str(started_at),
            mode=str(mode),
            score_level=score_level,
            score_conf=score_conf,
            total_scans=total_scans,
            total_findings=total_findings,
        )
    )
    story.append(PageBreak())

    # --- Page 2: dashboard exec (conservée) ---
    story.append(_standard_table([
        [_p(project, styles["h2"])],
        [_p(f"Cible: {target}", styles["body"])],
        [_p(f"Date: {started_at} | Mode: {mode}", styles["muted"])],
    ], [17.2 * cm], header_dark=False, repeat_header=False))

    story.append(Spacer(1, 6))
    story.append(_badge(f"GLOBAL RISK: {score_level}", score_level))
    story.append(Spacer(1, 4))
    story.append(_risk_gauge(score_level))
    story.append(Spacer(1, 6))

    kpi = _standard_table(
        [[
            Paragraph(f"<b>Scans</b><br/>{total_scans}", styles["body"]),
            Paragraph(f"<b>Findings</b><br/>{total_findings}", styles["body"]),
            Paragraph(f"<b>Sévérité max</b><br/>{score_level}", styles["body"]),
            Paragraph(f"<b>Confidence</b><br/>{score_conf}", styles["body"]),
        ]],
        [4.3 * cm, 4.3 * cm, 4.3 * cm, 4.3 * cm],
        header_dark=False,
        repeat_header=False,
    )
    story.append(kpi)
    story.append(Spacer(1, 8))

    takeaway = [
        "1) Corriger en priorité les findings HIGH/CRITICAL.",
        "2) Scan best-effort (pas d’exploitation): validation manuelle recommandée.",
        "3) Les preuves sont fournies pour audit et traçabilité.",
    ]
    story.append(_card([
        _p("À retenir en 30 secondes", styles["h2"]),
        _p("1) Corriger en priorité les findings HIGH/CRITICAL. 2) Scan best-effort (pas d’exploitation): validation manuelle recommandée. 3) Les preuves sont fournies pour audit et traçabilité.", styles["body"]),
    ], accent=_PALETTE["accent"]))

    # one page break here is OK
    story.append(PageBreak())

    # --- Page 2: Priorités absolues ---
    story.append(Paragraph("PRIORITÉS ABSOLUES", styles["h1"]))

    flat: List[Dict[str, Any]] = []
    for r in results:
        if str(r.get("status", "COMPLETED")).upper() == "ERROR":
            continue
        for f in r.get("findings", []) or []:
            flat.append({**f, "_scan_type": r.get("scan_type", "")})

    flat.sort(key=lambda f: (-_SEV_ORDER.index(_norm_sev(f.get("severity"))), -_CONF_ORDER.index(_norm_conf(f.get("confidence"))), f.get("title", "")))

    if not flat:
        story.append(_card([Paragraph("Aucune priorité détectée.", styles["body"])], accent=_sev_color("INFO")))
        story.append(PageBreak())
    else:
        data: List[List[Any]] = [[
            Paragraph("<b>Priorité</b>", styles["cell"]),
            Paragraph("<b>Finding</b>", styles["cell"]),
            Paragraph("<b>Sévérité</b>", styles["cell"]),
            Paragraph("<b>Impact</b>", styles["cell"]),
            Paragraph("<b>Action immédiate</b>", styles["cell"]),
            Paragraph("<b>Référence</b>", styles["cell"]),
        ]]

        for i, f in enumerate(flat[:10], start=1):
            sev = _norm_sev(f.get("severity"))
            scan_id = str(f.get("_scan_type", ""))
            scan_label = _humanize_scan_type(scan_id)

            # Important: make the identifier cassable by adding spaces around separators.
            scan_id_wrapped = _soft_wrap_identifier(scan_id)

            ref_cell = Paragraph(
                f"<b>{_escape(scan_label)}</b><br/><font size='7'><i>{_escape(scan_id_wrapped)}</i></font>",
                styles["cell_small"],
            )

            data.append([
                Paragraph(f"P{i}", styles["cell_small"]),
                Paragraph(_escape(f.get("title", "")), styles["cell_small"]),
                _badge(f"{_SEV_ICON.get(sev,'!')} {sev}", sev),
                Paragraph(_escape(f.get("risk", "")), styles["cell_small"]),
                Paragraph(_escape(f.get("recommendation", "")), styles["cell_small"]),
                ref_cell,
            ])

        story.append(
            _standard_table(
                data,
                # Make reference column wide enough; reduce other columns slightly.
                [1.1 * cm, 4.0 * cm, 1.9 * cm, 4.2 * cm, 4.0 * cm, 2.1 * cm],
                header_dark=True,
                repeat_header=True,
            )
        )
        story.append(PageBreak())

    # --- Page 3: Synthèse visuelle ---
    story.append(Paragraph("SYNTHÈSE VISUELLE", styles["h1"]))
    sev_counts = _normalize_sev_counts(summary.get("findings_by_severity", {}))
    story.append(_chart_findings_by_severity(sev_counts))
    story.append(Spacer(1, 6))
    story.append(_chart_scans_by_type(results))
    story.append(Spacer(1, 6))

    by_scan = summary.get("by_scan", []) or []
    if by_scan:
        data = [[
            Paragraph("<b>Sous-scan</b>", styles["cell"]),
            Paragraph("<b>Findings</b>", styles["cell"]),
            Paragraph("<b>Sévérité max</b>", styles["cell"]),
            Paragraph("<b>Confidence</b>", styles["cell"]),
            Paragraph("<b>Status</b>", styles["cell"]),
        ]]
        for r in by_scan:
            ms = _norm_sev(r.get("max_severity", "INFO"))
            scan_id = str(r.get("scan_type", ""))
            scan_label = _humanize_scan_type(scan_id)
            scan_id_wrapped = _soft_wrap_identifier(scan_id)
            scan_cell = Paragraph(
                f"<b>{_escape(scan_label)}</b><br/><font size='7'><i>{_escape(scan_id_wrapped)}</i></font>",
                styles["cell_small"],
            )
            data.append([
                scan_cell,
                Paragraph(str(r.get("findings", 0)), styles["cell_small"]),
                _badge(ms, ms),
                Paragraph(_escape(str(r.get("confidence", "low"))), styles["cell_small"]),
                Paragraph(_escape(str(r.get("status", "COMPLETED"))), styles["cell_small"]),
            ])
        story.append(
            _standard_table(
                data,
                # widen scan column to avoid 1-char wrapping
                [9.2 * cm, 1.2 * cm, 2.0 * cm, 1.8 * cm, 3.0 * cm],
                header_dark=False,
                repeat_header=True,
            )
        )

    story.append(PageBreak())

    # --- Details: content-driven (less forced breaks) ---
    story.append(Paragraph("DÉTAIL PAR SOUS-SCAN", styles["h1"]))
    story.append(Paragraph("Chaque sous-scan: identité (objectif) → findings → preuves techniques.", styles["muted"]))
    story.append(Spacer(1, 4))

    for scan in results:
        scan_type = scan.get("scan_type", "<unknown>")
        status = str(scan.get("status", "COMPLETED")).upper()
        sev = _norm_sev(scan.get("severity", "INFO"))
        conf = _norm_conf(scan.get("confidence", "low"))

        story.append(Spacer(1, 10))

        ident = _standard_table(
            [[
                _p(_humanize_scan_type(str(scan_type)), styles["body"]),
                _badge(sev, sev),
                _badge(conf.upper(), bg=_PALETTE["accent"]),
                _badge(status, bg=colors.HexColor("#6B7280") if status != "ERROR" else _sev_color("HIGH")),
            ]],
            [9.0 * cm, 2.2 * cm, 2.2 * cm, 3.8 * cm],
            header_dark=False,
            repeat_header=False,
        )

        objective = _p(
            "Objectif: détecter des mauvaises configurations A02 de manière automatisée (best-effort, sans exploitation).",
            styles["muted"],
        )

        story.append(KeepTogether([ident, objective, Spacer(1, 6)]))

        if status == "ERROR":
            story.append(_make_error_box(scan, styles))
            story.append(Spacer(1, 6))
            md = scan.get("metadata", {}) or {}
            err = _strip_to_one_line(str(md.get("error") or "N/A"))
            story.append(_evidence_box(err, styles))
            continue

        findings = scan.get("findings", []) or []
        if findings:
            story.append(_make_findings_table(findings, styles))
            story.append(Spacer(1, 6))
        else:
            # Compact "no findings" + a small summary table to avoid empty pages
            story.append(_badge("Aucun problème détecté", bg=_sev_color("INFO")))
            story.append(Spacer(1, 4))
            md = scan.get("metadata", {}) or {}
            summary_rows = [
                [Paragraph("<b>Résumé du test</b>", styles["cell"]), Paragraph("<b>Valeur</b>", styles["cell"])],
                [Paragraph("Cible", styles["cell_small"]), Paragraph(_escape(str(scan.get("target", "N/A"))), styles["cell_small"])],
                [Paragraph("Éléments testés", styles["cell_small"]), Paragraph(_escape(str(md.get("tested", md.get("ports", md.get("endpoints", "N/A"))))), styles["cell_small"])],
                [Paragraph("Codes HTTP rencontrés", styles["cell_small"]), Paragraph(_escape(str(md.get("status_codes", "N/A"))), styles["cell_small"])],
            ]
            story.append(_standard_table(summary_rows, [6.0 * cm, 11.2 * cm], header_dark=False, repeat_header=False))
            story.append(Spacer(1, 6))

            # Add a small, high-value guidance box to avoid empty space and improve UX
            story.append(
                _card(
                    [
                        Paragraph("<b>Validation manuelle recommandée</b>", styles["body"]),
                        Paragraph(
                            _escape(
                                "Ce sous-scan est best-effort. Si ce composant existe dans la cible (XML/Soap/API), "
                                "valider manuellement: type de contenu accepté, parsing XML, et messages d’erreur serveur."
                            ),
                            styles["body"],
                        ),
                    ],
                    accent=_PALETTE["accent"],
                )
            )
            story.append(Spacer(1, 6))

        evidence = scan.get("evidence") or "No raw evidence captured."
        story.append(_evidence_box(evidence, styles))

    # --- Conclusion & Plan d’actions ---
    # Improve structure and fill page with a 2-column grid cards
    story.append(PageBreak())
    story.append(Paragraph("CONCLUSION & PLAN D’ACTIONS", styles["h1"]))

    conclusion_left = _card(
        [
            Paragraph(
                _escape(
                    "Conclusion — Les mauvaises configurations augmentent la surface d’attaque (services exposés, en-têtes manquants, endpoints sensibles). "
                    "Les résultats ci-dessous permettent de prioriser un durcissement rapide."
                ),
                styles["body"],
            ),
            Paragraph(
                _escape(
                    "Responsabilité: Ce rapport est basé sur des tests automatisés best-effort et ne remplace pas un audit manuel complet."
                ),
                styles["muted"],
            ),
        ],
        accent=_sev_color(score_level),
        width=8.4 * cm,
    )

    conclusion_right = _card(
        [
            Paragraph("<b>Limites & validation recommandée</b>", styles["body"]),
            Paragraph(
                _escape(
                    "Valider manuellement les points HIGH/CRITICAL: configuration serveur (TRACE/PUT), contrôle d’accès (403/401), exposition réseau, et fichiers sensibles. "
                    "Un WAF ou un filtrage réseau peut modifier la visibilité de certains tests."
                ),
                styles["body"],
            ),
        ],
        accent=_PALETTE["accent"],
        width=8.4 * cm,
    )

    story.append(Table([[conclusion_left, conclusion_right]], colWidths=[8.6 * cm, 8.6 * cm], style=TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)])))
    story.append(Spacer(1, 10))

    # Keep rest of existing plan table but with a clearer layout
    top_actions = _collect_top_actions(results, limit=5)
    if not top_actions:
        story.append(_card([Paragraph("Aucun finding prioritaire détecté par ce scan automatisé.", styles["body"])], accent=_sev_color("INFO")))
        doc.build(story)
        return output_path

    # Plan d'actions priorisé (tableau clair)
    plan_data: List[List[Any]] = [[
        Paragraph("<b>Priorité</b>", styles["cell"]),
        Paragraph("<b>Problème</b>", styles["cell"]),
        Paragraph("<b>Impact</b>", styles["cell"]),
        Paragraph("<b>Action recommandée</b>", styles["cell"]),
        Paragraph("<b>Sévérité</b>", styles["cell"]),
    ]]

    for i, a in enumerate(top_actions, start=1):
        sev = _norm_sev(a.get("severity", "INFO"))
        plan_data.append([
            Paragraph(f"P{i}", styles["cell_small"]),
            Paragraph(_escape(a.get("title", "")), styles["cell_small"]),
            Paragraph(_escape(a.get("why", "")), styles["cell_small"]),
            Paragraph(_escape(a.get("action", "")), styles["cell_small"]),
            _badge(sev, sev),
        ])

    story.append(_standard_table(plan_data, [1.2 * cm, 5.0 * cm, 5.0 * cm, 4.0 * cm, 2.0 * cm], header_dark=True, repeat_header=True))
    story.append(Spacer(1, 8))

    # Prochaines étapes (texte fluide, pas bullets secs)
    story.append(
        _card(
            [
                Paragraph("<b>Prochaines étapes</b>", styles["body"]),
                Paragraph(
                    _escape(
                        "Après correction, relancer le scan pour vérifier l’efficacité du durcissement. "
                        "Pour les points HIGH/CRITICAL, effectuer une validation manuelle (configuration serveur, règles firewall/WAF, endpoints sensibles)."
                    ),
                    styles["body"],
                ),
            ],
            accent=_PALETTE["accent"],
        )
    )

    doc.build(story)
    return output_path


# --- Helpers: safe html for Paragraph content ---

def _safe_inline_html(s: Any) -> str:
    """Sanitize text but keep safe inline HTML tags already authored by us.

    We still unescape entities and strip invisible chars, but we do NOT escape <br/> etc.
    This is used for small, controlled snippets like 'label + small code line'.
    """

    return _sanitize_text(s)


# --- CLI helper (optional but very useful for quick regen from JSON) ---

def _load_json(path: str) -> Dict[str, Any]:
    import json

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def main(argv=None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Generate A02 PDF report from aggregated JSON")
    ap.add_argument("--in", dest="inp", required=True, help="Aggregated results JSON path")
    ap.add_argument("--out", dest="out", required=True, help="Output PDF path")
    args = ap.parse_args(argv)

    aggregated = _load_json(args.inp)
    generate_pdf_report(aggregated, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


