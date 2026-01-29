"""Sanity checker for aggregated JSON results used for PDF reporting.

Goals (PFE / audit quality):
- Validate strict finding schema
- Validate scan-level severity/status coherence
- Ensure required blocks exist (identity/findings/evidence) for each scan

Usage:
  python -m a02_security_misconfiguration.runner.report_sanity_check --in results.json

Exit codes:
  0 = OK
  2 = validation failures
"""

from __future__ import annotations

import argparse
import json
from typing import Any, Dict, List


_SEV = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
_CONF = {"low", "medium", "high"}
_STATUS = {"COMPLETED", "PARTIAL", "ERROR"}


def _rank_sev(s: str) -> int:
    order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    s = str(s or "INFO").upper()
    return order.index(s) if s in order else 0


def _max_sev(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "INFO"
    return max((str(f.get("severity", "INFO")).upper() for f in findings), key=_rank_sev)


def validate(payload: Dict[str, Any]) -> List[str]:
    errors: List[str] = []

    results = payload.get("results") or []
    if not isinstance(results, list):
        return ["'results' must be a list"]

    for r in results:
        scan = r.get("scan_type", "<unknown>")

        status = str(r.get("status", "COMPLETED")).upper()
        if status not in _STATUS:
            errors.append(f"{scan}: invalid status '{status}'")

        sev = str(r.get("severity", "INFO")).upper()
        if sev not in _SEV:
            errors.append(f"{scan}: invalid severity '{sev}'")

        conf = str(r.get("confidence", "low")).lower()
        if conf not in _CONF:
            errors.append(f"{scan}: invalid confidence '{conf}'")

        if "evidence" not in r:
            errors.append(f"{scan}: missing scan evidence field")

        findings = r.get("findings") or []
        if not isinstance(findings, list):
            errors.append(f"{scan}: findings must be list")
            continue

        # If completed/partial, severity must match max finding severity (or INFO)
        expected = _max_sev(findings)
        if status in {"COMPLETED", "PARTIAL"} and sev != expected:
            errors.append(f"{scan}: scan severity '{sev}' != max finding severity '{expected}'")

        for i, f in enumerate(findings, start=1):
            prefix = f"{scan}/F{i}"
            required = ["title", "severity", "confidence", "risk", "evidence", "recommendation", "confidence_reason"]
            for k in required:
                if k not in f:
                    errors.append(f"{prefix}: missing field '{k}'")

            fsev = str(f.get("severity", "INFO")).upper()
            if fsev not in _SEV:
                errors.append(f"{prefix}: invalid severity '{fsev}'")

            fconf = str(f.get("confidence", "low")).lower()
            if fconf not in _CONF:
                errors.append(f"{prefix}: invalid confidence '{fconf}'")

            # Avoid common UX concat issues in titles
            title = str(f.get("title", ""))
            for bad in ["HIGH", "MEDIUM", "LOW", "CRITICAL", "INFO"]:
                if title.endswith(bad) and not title.endswith(" " + bad):
                    errors.append(f"{prefix}: suspicious title concatenation '{title}'")

        if status == "ERROR":
            md = r.get("metadata") or {}
            if not md.get("error"):
                errors.append(f"{scan}: status ERROR but metadata.error missing")
            if not md.get("error_cause"):
                errors.append(f"{scan}: status ERROR but metadata.error_cause missing")
            if not md.get("error_recommendation"):
                errors.append(f"{scan}: status ERROR but metadata.error_recommendation missing")

    return errors


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Sanity-check A02 aggregated JSON for reporting")
    ap.add_argument("--in", dest="inp", required=True, help="Path to aggregated results JSON")
    args = ap.parse_args(argv)

    with open(args.inp, "r", encoding="utf-8") as f:
        payload = json.load(f)

    errs = validate(payload)
    if errs:
        print("SANITY CHECK: FAIL")
        for e in errs:
            print("-", e)
        return 2

    print("SANITY CHECK: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
