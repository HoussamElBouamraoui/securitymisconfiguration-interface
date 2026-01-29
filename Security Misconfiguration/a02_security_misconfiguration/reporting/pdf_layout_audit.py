"""Automated UX/print audit for generated PDF reports.

This is a best-effort heuristic used during development to detect:
- Page density too low (large useless whitespace)
- Potential 'letter-by-letter' wrapping (many 1-char tokens)

It does NOT guarantee perfect visual output, but helps catch regressions.

Usage:
  python -m a02_security_misconfiguration.reporting.pdf_layout_audit --pdf report.pdf
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass

import pdfplumber


@dataclass
class PageAudit:
    page: int
    fill: float
    words: int
    one_char_words: int


def audit_pdf(path: str) -> list[PageAudit]:
    out: list[PageAudit] = []
    with pdfplumber.open(path) as pdf:
        for i, p in enumerate(pdf.pages, start=1):
            words = p.extract_words(x_tolerance=1, y_tolerance=1, keep_blank_chars=False)
            if not words:
                out.append(PageAudit(i, 0.0, 0, 0))
                continue
            minx = min(w["x0"] for w in words)
            maxx = max(w["x1"] for w in words)
            miny = min(w["top"] for w in words)
            maxy = max(w["bottom"] for w in words)
            fill = ((maxx - minx) * (maxy - miny)) / (p.width * p.height)
            one_char = sum(1 for w in words if len(w["text"]) == 1)
            out.append(PageAudit(i, fill, len(words), one_char))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Heuristic layout audit for PDF")
    ap.add_argument("--pdf", required=True, help="PDF path")
    ap.add_argument("--min-fill", type=float, default=0.28, help="Minimum bbox-fill ratio expected")
    ap.add_argument("--max-one-char", type=int, default=25, help="Maximum one-char words per page")
    args = ap.parse_args(argv)

    audits = audit_pdf(args.pdf)
    bad = []
    for a in audits:
        if a.page == 1:
            # allow cover to be less dense
            continue
        if a.fill < args.min_fill:
            bad.append(f"page {a.page}: low fill {a.fill:.2f}")
        if a.one_char_words > args.max_one_char:
            bad.append(f"page {a.page}: too many 1-char tokens ({a.one_char_words})")

    if bad:
        print("PDF LAYOUT AUDIT: FAIL")
        for b in bad:
            print("-", b)
        return 2

    print("PDF LAYOUT AUDIT: PASS")
    for a in audits:
        print(f"page {a.page}: fill={a.fill:.2f} words={a.words} one_char={a.one_char_words}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
