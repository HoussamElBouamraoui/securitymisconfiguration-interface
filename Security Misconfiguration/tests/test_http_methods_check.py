from a02_security_misconfiguration.core.base_check import CheckConfig
from a02_security_misconfiguration.web.http_methods_aggressive import HTTPMethodsAggressive


def test_http_methods_returns_result_on_unreachable_target():
    # Use a port likely closed on localhost to force connection error quickly.
    cfg = CheckConfig(connect_timeout=0.2, read_timeout=0.2, retries=0)
    check = HTTPMethodsAggressive(cfg)
    r = check.run("http://127.0.0.1:9")
    d = r.to_dict()
    assert d["scan_type"] == "A02_HTTP_Methods_Aggressive"
    assert d["target"] == "http://127.0.0.1:9"
    assert d["status"] in ("completed", "error")
    assert "timestamp" in d
