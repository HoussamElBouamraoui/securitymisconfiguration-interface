"""Result objects and serialization helpers for A02 Security Misconfiguration checks."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_CONFIDENCES = {"low", "medium", "high"}


def _norm_sev(sev: str) -> str:
    s = (sev or "INFO").strip().upper()
    return s if s in _SEVERITIES else "INFO"


def _norm_conf(conf: str) -> str:
    c = (conf or "low").strip().lower()
    return c if c in _CONFIDENCES else "low"


def _default_confidence_reason(confidence: str) -> str:
    c = _norm_conf(confidence)
    if c == "high":
        return "Direct evidence collected by automated checks."
    if c == "medium":
        return "Strong indicators observed; manual validation recommended to confirm impact."
    return "Best-effort / heuristic signal; manual validation recommended."


@dataclass
class Finding:
    """A single finding produced by a check (strict normalized schema)."""

    title: str
    severity: str = "INFO"  # INFO|LOW|MEDIUM|HIGH|CRITICAL
    confidence: str = "medium"  # low|medium|high
    risk: str = ""
    evidence: str = ""
    recommendation: str = ""

    # Academic transparency: why confidence is low/medium/high.
    # Required by UX for defensible output.
    confidence_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        conf = _norm_conf(self.confidence)
        out: Dict[str, Any] = {
            "title": self.title,
            "severity": _norm_sev(self.severity),
            "confidence": conf,
            "risk": self.risk,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            # Always present for transparency
            "confidence_reason": self.confidence_reason or _default_confidence_reason(conf),
        }
        return out


@dataclass
class ScanResult:
    """Structured output for every check."""

    scan_type: str
    target: str

    status: str = "completed"  # completed|error|skipped
    severity: str = "INFO"  # INFO|LOW|MEDIUM|HIGH|CRITICAL
    confidence: str = "medium"  # low|medium|high

    findings: List[Finding] = field(default_factory=list)

    # Technical evidence/logs at scan level
    evidence: str = ""

    timestamp: str = field(default_factory=utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def add_finding(
        self,
        *,
        title: str,
        severity: str = "INFO",
        confidence: str = "medium",
        risk: str = "",
        evidence: str = "",
        recommendation: str = "",
        confidence_reason: str = "",
        **legacy_kwargs: Any,
    ) -> None:
        """Add a strict finding.

        Compatibility layer:
        - Accept legacy kwargs used by older checks (description, remediation, raw_output)
        - Map them into the strict schema instead of raising TypeError

        This prevents a single schema mismatch from turning a scan into ERROR.
        """

        # Legacy mapping (best-effort)
        if legacy_kwargs:
            # description is often a risk/impact textual explanation
            if not risk and isinstance(legacy_kwargs.get("description"), str):
                risk = legacy_kwargs.get("description")
            # remediation was previous name for recommendation
            if not recommendation and isinstance(legacy_kwargs.get("remediation"), str):
                recommendation = legacy_kwargs.get("remediation")
            # raw_output can be appended to evidence when evidence missing
            if not evidence and isinstance(legacy_kwargs.get("raw_output"), str):
                evidence = legacy_kwargs.get("raw_output")

            # Store unknown legacy fields for debugging, but do not crash
            unknown = {k: v for k, v in legacy_kwargs.items() if k not in {"description", "remediation", "raw_output"}}
            if unknown:
                self.metadata.setdefault("legacy_fields", []).append({"title": title, "unknown": list(unknown.keys())})

        self.findings.append(
            Finding(
                title=title,
                severity=severity,
                confidence=confidence,
                risk=risk,
                evidence=evidence,
                recommendation=recommendation,
                confidence_reason=confidence_reason,
            )
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_type": self.scan_type,
            "target": self.target,
            "status": self.status,
            "severity": _norm_sev(self.severity),
            "confidence": _norm_conf(self.confidence),
            "findings": [f.to_dict() for f in self.findings],
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_error(cls, *, scan_type: str, target: str, error: Exception, evidence: str = "") -> "ScanResult":
        r = cls(scan_type=scan_type, target=target, status="error", severity="INFO", confidence="low")
        r.evidence = evidence or f"{type(error).__name__}: {error}"
        r.metadata["error_type"] = type(error).__name__
        return r
