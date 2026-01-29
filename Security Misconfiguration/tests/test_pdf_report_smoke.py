import os

from a02_security_misconfiguration.reporting.pdf_report import generate_pdf_report


def test_pdf_report_generation(tmp_path):
    aggregated = {
        "target": "http://example.com",
        "status": "completed",
        "mode": "aggressive",
        "project": "Pentest Assistant",
        "started_at": "2026-01-25T12:00:00",
        "duration_seconds": 1.234,
        "results": [
            {
                "scan_type": "A02_Test",
                "target": "http://example.com",
                "status": "completed",
                "severity": "high",
                "confidence": "high",
                "findings": [
                    {
                        "title": "Test finding",
                        "description": "Desc",
                        "severity": "high",
                        "confidence": "high",
                        "risk": "Risk",
                        "evidence": "Evidence",
                        "remediation": "Fix",
                    }
                ],
                "evidence": "raw evidence",
                "timestamp": "2026-01-25T12:00:00",
                "metadata": {},
            }
        ],
        "summary": {
            "total_scans": 1,
            "total_findings": 1,
            "findings_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "scans_by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "overall_severity": "high",
            "overall_confidence": "high",
        },
        "metadata": {"workers": 1, "checks": 1},
    }

    out = tmp_path / "report.pdf"
    generate_pdf_report(aggregated, str(out))
    assert out.exists()
    assert os.path.getsize(out) > 1000
