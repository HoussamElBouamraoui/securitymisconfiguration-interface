import json

from a02_security_misconfiguration.core.result import ScanResult


def test_scanresult_to_dict_schema_minimal():
    r = ScanResult(scan_type="X", target="t")
    r.add_finding(
        title="T",
        severity="HIGH",
        confidence="high",
        risk="Risk",
        evidence="Evidence",
        recommendation="Fix",
    )
    d = r.to_dict()

    for k in [
        "scan_type",
        "target",
        "status",
        "severity",
        "confidence",
        "findings",
        "evidence",
        "timestamp",
        "metadata",
    ]:
        assert k in d

    assert d["severity"] in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert d["confidence"] in ("low", "medium", "high")

    assert isinstance(d["findings"], list) and d["findings"]
    f = d["findings"][0]
    for k in ["title", "severity", "confidence", "risk", "evidence", "recommendation"]:
        assert k in f

    assert f["severity"] in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert f["confidence"] in ("low", "medium", "high")

    json.dumps(d)
