"""Aggressive cookie flags inspection (Secure/HttpOnly/SameSite)."""

from __future__ import annotations

import re

from ..core.base_check import BaseCheck
from ..core.utils import http_request, normalize_target, requests_session, safe_truncate


SET_COOKIE_RE = re.compile(r"(?i)^\s*([^=\s]+)=")


class CookieFlagsAggressive(BaseCheck):
    scan_type = "A02_Cookie_Flags_Aggressive"

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

        raw_set_cookies = []
        if hasattr(r.raw, "headers") and hasattr(r.raw.headers, "get_all"):
            raw_set_cookies = r.raw.headers.get_all("Set-Cookie") or []
        else:
            sc = r.headers.get("Set-Cookie")
            if sc:
                raw_set_cookies = [sc]

        for sc in raw_set_cookies:
            name_m = SET_COOKIE_RE.search(sc)
            name = name_m.group(1) if name_m else "<unknown>"
            low = sc.lower()
            secure = "secure" in low
            httponly = "httponly" in low
            samesite = "samesite=" in low

            if url.lower().startswith("https://") and not secure:
                res.add_finding(
                    title="Cookie missing Secure flag",
                    severity="MEDIUM",
                    confidence="high",
                    risk="Cookies without Secure may be sent over HTTP, enabling interception.",
                    evidence=f"{name}: {safe_truncate(sc, 500)}",
                    recommendation="Set the Secure attribute for session and sensitive cookies on HTTPS.",
                    confidence_reason="Direct evidence from Set-Cookie header.",
                )
            if not httponly:
                res.add_finding(
                    title="Cookie missing HttpOnly flag",
                    severity="MEDIUM",
                    confidence="high",
                    risk="Cookies without HttpOnly may be accessible to JavaScript (XSS impact).",
                    evidence=f"{name}: {safe_truncate(sc, 500)}",
                    recommendation="Set the HttpOnly attribute for session and sensitive cookies.",
                    confidence_reason="Direct evidence from Set-Cookie header.",
                )
            if not samesite:
                res.add_finding(
                    title="Cookie missing SameSite attribute",
                    severity="LOW",
                    confidence="high",
                    risk="Cookies without SameSite attribute are vulnerable to CSRF attacks.",
                    evidence=f"{name}: {safe_truncate(sc, 500)}",
                    recommendation="Set the SameSite attribute for cookies to mitigate CSRF risks.",
                    confidence_reason="Direct evidence from Set-Cookie header.",
                )

        res.evidence = safe_truncate(
            f"Status: {r.status_code}\nSet-Cookie headers:\n" + "\n".join(raw_set_cookies),
            8000,
        )
        res.metadata["final_url"] = str(getattr(r, "url", url))
        res.metadata["status_code"] = r.status_code
        return res
