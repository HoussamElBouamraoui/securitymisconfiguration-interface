"""Scoring and normalization helpers.

This module is intentionally pure/side-effect free: it only transforms dicts.

Goals:
- reduce false positives by attaching a confidence to each finding
- compute a smarter scan-level severity from findings + context
- compute an A02 Global Risk Score (explanatory, not marketing)
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Tuple

SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
CONFIDENCE_ORDER = ["low", "medium", "high"]


def normalize_severity(value: str) -> str:
    v = (value or "INFO").upper().strip()
    return v if v in SEVERITY_ORDER else "INFO"


def normalize_confidence(value: str) -> str:
    v = (value or "low").lower().strip()
    return v if v in CONFIDENCE_ORDER else "low"


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.index(normalize_severity(sev))


def confidence_rank(conf: str) -> int:
    return CONFIDENCE_ORDER.index(normalize_confidence(conf))


def max_severity(severities: Iterable[str]) -> str:
    best = "INFO"
    for s in severities:
        if severity_rank(s) > severity_rank(best):
            best = normalize_severity(s)
    return best


def max_confidence(confidences: Iterable[str]) -> str:
    best = "low"
    for c in confidences:
        if confidence_rank(c) > confidence_rank(best):
            best = normalize_confidence(c)
    return best


def weighted_severity(severity: str, confidence: str) -> str:
    """Lower severity if confidence is low/medium.

    This avoids exaggerated alerts:
    - high confidence: keep severity
    - medium confidence: drop 1 level for HIGH/CRITICAL
    - low confidence: drop 1–2 levels for MEDIUM/HIGH/CRITICAL
    """

    s = normalize_severity(severity)
    c = normalize_confidence(confidence)

    drop = 0
    if c == "medium":
        drop = 1 if s in ("CRITICAL", "HIGH") else 0
    elif c == "low":
        drop = 2 if s == "CRITICAL" else 1 if s in ("HIGH", "MEDIUM") else 0

    idx = max(0, severity_rank(s) - drop)
    return SEVERITY_ORDER[idx]


def derive_scan_severity(findings: List[Dict]) -> Tuple[str, str]:
    weighted = [weighted_severity(f.get("severity", "INFO"), f.get("confidence", "low")) for f in findings]
    confs = [normalize_confidence(f.get("confidence", "low")) for f in findings]
    return max_severity(weighted), max_confidence(confs)


def severity_counts(results: List[Dict]) -> Dict[str, int]:
    out = {k: 0 for k in SEVERITY_ORDER}
    for r in results:
        sev = normalize_severity(r.get("severity", "INFO"))
        out[sev] += 1
    return out


def findings_count_by_severity(results: List[Dict]) -> Dict[str, int]:
    out = {k: 0 for k in SEVERITY_ORDER}
    for r in results:
        for f in r.get("findings", []) or []:
            sev = normalize_severity(f.get("severity", "INFO"))
            out[sev] += 1
    return out


def compute_a02_risk_score(results: List[Dict]) -> Dict[str, str]:
    """Compute an explanatory A02 Risk Score.

    Score is based on finding severities weighted by confidence.
    Returns {level, confidence, explanation}.
    """

    points = 0.0
    max_conf = "low"

    sev_points = {"CRITICAL": 5, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    conf_weight = {"high": 1.0, "medium": 0.7, "low": 0.4}

    for r in results:
        for f in r.get("findings", []) or []:
            s = normalize_severity(f.get("severity", "INFO"))
            c = normalize_confidence(f.get("confidence", "low"))
            points += sev_points[s] * conf_weight[c]
            if confidence_rank(c) > confidence_rank(max_conf):
                max_conf = c

    # Simple thresholds (transparent)
    if points >= 12:
        level = "HIGH"
    elif points >= 6:
        level = "MEDIUM"
    elif points >= 2:
        level = "LOW"
    else:
        level = "INFO"

    explanation = (
        f"Score basé sur la somme pondérée des findings (CRITICAL=5, HIGH=3, MEDIUM=2, LOW=1) multipliée par un poids de confiance (high=1.0, medium=0.7, low=0.4). Total={points:.2f}."
    )

    return {"level": level, "confidence": max_conf, "explanation": explanation}
