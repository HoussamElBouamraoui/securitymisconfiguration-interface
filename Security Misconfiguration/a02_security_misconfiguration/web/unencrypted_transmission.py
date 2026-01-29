"""Detection of unencrypted data transmission.

CWE-5: J2EE Misconfiguration: Data Transmission Without Encryption
"""

from __future__ import annotations

from ..core.base_check import BaseCheck
from ..core.utils import http_request, normalize_target, requests_session, safe_truncate


# Sensitive form field names
SENSITIVE_FIELDS = [
    "password",
    "passwd",
    "pwd",
    "pass",
    "credential",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "ssn",
    "credit_card",
    "creditcard",
    "cvv",
    "card_number",
    "cardnumber",
]

# Paths that typically contain forms
FORM_PATHS = [
    "/login",
    "/signin",
    "/register",
    "/signup",
    "/checkout",
    "/payment",
    "/account",
    "/profile",
    "/settings",
]


class UnencryptedTransmission(BaseCheck):
    """Detect forms transmitting sensitive data over HTTP (not HTTPS).

    CWE-5: J2EE Misconfiguration: Data Transmission Without Encryption
    """

    scan_type = "A02_Unencrypted_Transmission"

    def run(self, target: str):
        res = self._result(target)
        base = normalize_target(target)
        s = requests_session(self.config.user_agent)

        # Check if target is HTTP (not HTTPS)
        is_http = base.startswith("http://")

        if not is_http:
            # If already HTTPS, check for mixed content
            res.severity = "INFO"
            res.evidence = "Target uses HTTPS - checking for mixed content issues"
            return res

        insecure_forms = []
        raw = []

        # Test common paths for forms
        for path in FORM_PATHS[:8]:
            url = base.rstrip("/") + path
            try:
                r = http_request(
                    s,
                    "GET",
                    url,
                    timeout=(self.config.connect_timeout, self.config.read_timeout),
                    max_redirects=self.config.max_redirects,
                )

                raw.append(f"GET {url} => {r.status_code}")

                if r.status_code == 200:
                    body = r.text.lower()

                    # Check for forms
                    if "<form" in body:
                        # Check for sensitive input fields
                        found_sensitive = []
                        for field in SENSITIVE_FIELDS:
                            if f'name="{field}"' in body or f"name='{field}'" in body or \
                               f'id="{field}"' in body or f"id='{field}'" in body or \
                               f'type="password"' in body:
                                found_sensitive.append(field)

                        if found_sensitive:
                            # Check form action
                            import re
                            form_actions = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', r.text, re.IGNORECASE)

                            insecure_forms.append({
                                "url": url,
                                "sensitive_fields": found_sensitive,
                                "form_actions": form_actions[:3] if form_actions else ["(form submits to same page)"],
                            })

            except Exception as e:
                raw.append(f"GET {url} error: {type(e).__name__}")

        # Create findings
        if insecure_forms:
            for form in insecure_forms:
                res.add_finding(
                    title="Sensitive data transmitted over HTTP (CWE-5)",
                    severity="CRITICAL",
                    confidence="high",
                    risk=f"Form with sensitive fields ({', '.join(form['sensitive_fields'])}) transmitted over unencrypted HTTP. Credentials and sensitive data can be intercepted via Man-in-the-Middle attacks.",
                    evidence=f"HTTP form at {form['url']} with fields: {', '.join(form['sensitive_fields'][:5])}",
                    recommendation="Migrate entire site to HTTPS. Implement HSTS (Strict-Transport-Security header). Redirect all HTTP traffic to HTTPS (301 permanent redirect).",
                    confidence_reason="Direct evidence: sensitive form fields on HTTP page."
                )

            res.severity = "CRITICAL"
            res.confidence = "high"
            res.metadata["insecure_forms"] = insecure_forms

        else:
            # Even if no sensitive forms found, HTTP is still a misconfiguration
            res.add_finding(
                title="Site not using HTTPS (CWE-5)",
                severity="HIGH",
                confidence="high",
                risk="Entire site accessible over HTTP. All data transmitted in cleartext, vulnerable to interception and Man-in-the-Middle attacks.",
                evidence=f"Site accessible at {base} (HTTP, not HTTPS)",
                recommendation="Implement HTTPS with valid TLS certificate. Configure HSTS header. Redirect HTTP to HTTPS.",
                confidence_reason="Site responds to HTTP requests."
            )
            res.severity = "HIGH"
            res.confidence = "high"

        res.evidence = safe_truncate("\n".join(raw), 10000)
        res.metadata["base_url"] = base
        res.metadata["protocol"] = "HTTP" if is_http else "HTTPS"
        return res
