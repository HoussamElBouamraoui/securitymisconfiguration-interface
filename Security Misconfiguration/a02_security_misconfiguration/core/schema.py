"""Schema helpers for strict normalization.

Defines the canonical field names for findings and scan results.
"""

from __future__ import annotations

FINDING_FIELDS = [
    "title",
    "severity",  # INFO/LOW/MEDIUM/HIGH/CRITICAL
    "confidence",  # low/medium/high
    "risk",
    "evidence",
    "recommendation",
]

SCAN_RESULT_FIELDS = [
    "scan_type",
    "target",
    "status",
    "severity",
    "confidence",
    "findings",
    "evidence",
    "timestamp",
    "metadata",
]
