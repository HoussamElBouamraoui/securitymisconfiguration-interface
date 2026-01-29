"""Check for missing/misconfigured security headers."""

from __future__ import annotations

from ..core.base_check import BaseCheck
from ..core.utils import http_request, normalize_target, requests_session, safe_truncate


RECOMMENDED_HEADERS = {
    "Content-Security-Policy": "Missing CSP can enable XSS and content injection.",
    "Strict-Transport-Security": "Missing HSTS can allow SSL stripping on HTTPS sites.",
    "X-Frame-Options": "Missing X-Frame-Options can enable clickjacking.",
    "X-Content-Type-Options": "Missing X-Content-Type-Options can allow MIME sniffing.",
    "Referrer-Policy": "Missing Referrer-Policy can leak sensitive URLs via referrer.",
    "Permissions-Policy": "Missing Permissions-Policy may allow unnecessary browser features.",
    "X-XSS-Protection": "Missing X-XSS-Protection leaves older browsers vulnerable to XSS.",
    "Cross-Origin-Embedder-Policy": "Missing COEP can expose resources via cross-origin.",
    "Cross-Origin-Opener-Policy": "Missing COOP can leak data via window references.",
    "Cross-Origin-Resource-Policy": "Missing CORP may allow unauthorized resource embedding.",
}

# Headers dangereux qui ne devraient pas être exposés
DANGEROUS_HEADERS = {
    "Server": "Server header exposes technology stack information.",
    "X-Powered-By": "X-Powered-By header reveals framework/language version.",
    "X-AspNet-Version": "ASP.NET version header leaks technology details.",
    "X-AspNetMvc-Version": "ASP.NET MVC version header leaks framework details.",
    "X-Generator": "Generator header may reveal CMS or framework.",
}


class HeadersSecurityCheck(BaseCheck):
    scan_type = "A02_Headers_Security_Check"

    def run(self, target: str):
        res = self._result(target)
        url = normalize_target(target)
        s = requests_session(self.config.user_agent)

        try:
            r = http_request(
                s,
                "GET",
                url,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                max_redirects=self.config.max_redirects,
            )
        except Exception as e:
            return type(res).from_error(scan_type=self.scan_type, target=target, error=e)

        missing = []
        present = {k.lower(): v for k, v in r.headers.items()}
        for h, why in RECOMMENDED_HEADERS.items():
            if h.lower() not in present:
                missing.append((h, why))

        # HSTS only meaningful on HTTPS
        if url.lower().startswith("http://"):
            missing = [(h, why) for (h, why) in missing if h != "Strict-Transport-Security"]

        # Check for dangerous headers that should not be exposed
        dangerous_present = []
        for h, why in DANGEROUS_HEADERS.items():
            if h.lower() in present:
                dangerous_present.append((h, present[h.lower()], why))

        # Report dangerous headers
        for h, value, why in dangerous_present:
            res.add_finding(
                title=f"Information disclosure via header: {h}",
                severity="LOW",
                confidence="high",
                risk=why,
                evidence=f"{h}: {value}",
                recommendation="Remove or obfuscate technology fingerprinting headers at the web server level.",
                confidence_reason="Direct evidence from HTTP response headers.",
            )

        # Report missing security headers
        for h, why in missing:
            if h == "Strict-Transport-Security":
                sev = "MEDIUM"
            elif h == "Content-Security-Policy":
                sev = "MEDIUM"
            else:
                sev = "LOW"

            res.add_finding(
                title=f"Missing security header: {h}",
                severity=sev,
                confidence="high",
                risk=why,
                evidence=f"Response headers do not include '{h}' (status={r.status_code})",
                recommendation="Configure recommended security headers at the web server / reverse proxy level.",
                confidence_reason="Direct evidence from HTTP response headers.",
            )

        if res.findings:
            res.severity = max((f.severity for f in res.findings), default="INFO")
            res.confidence = "high"

        res.evidence = safe_truncate(
            f"Status: {r.status_code}\nResponse headers:\n" + "\n".join([f"{k}: {v}" for k, v in r.headers.items()]),
            8000,
        )
        res.metadata["final_url"] = str(getattr(r, "url", url))
        res.metadata["status_code"] = r.status_code
        return res
