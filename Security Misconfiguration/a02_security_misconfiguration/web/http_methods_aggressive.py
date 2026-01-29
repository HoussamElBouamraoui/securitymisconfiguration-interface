"""Aggressive probing of dangerous HTTP methods (TRACE/PUT/DELETE/CONNECT)."""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.base_check import BaseCheck
from ..core.utils import (
    http_request,
    normalize_target,
    requests_session,
    safe_truncate,
    sleep_backoff,
)


DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE", "CONNECT", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"]


class HTTPMethodsAggressive(BaseCheck):
    scan_type = "A02_HTTP_Methods_Aggressive"

    def run(self, target: str):
        res = self._result(target)
        base = normalize_target(target)
        s = requests_session(self.config.user_agent)

        raw = []
        allowed = []  # (method, url, status, reason)

        try:
            ro = http_request(
                s,
                "OPTIONS",
                base,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                max_redirects=self.config.max_redirects,
                max_bytes=32 * 1024,
            )
            raw.append(f"OPTIONS {base} => {ro.status_code} allow={ro.headers.get('Allow','')} final={getattr(ro,'url',base)}")
            allow_hdr = (ro.headers.get("Allow") or "")
            if allow_hdr:
                for m in DANGEROUS_METHODS:
                    if m in allow_hdr.upper():
                        allowed.append((m, base, ro.status_code, f"Allow header: {allow_hdr}"))
        except Exception as e:
            return type(res).from_error(scan_type=self.scan_type, target=target, error=e)

        # Add a light HEAD probe on base to detect weird method handling quickly.
        try:
            rh = http_request(
                s,
                "HEAD",
                base,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                max_redirects=self.config.max_redirects,
                max_bytes=8 * 1024,
            )
            raw.append(f"HEAD {base} => {rh.status_code} final={getattr(rh,'url',base)}")
        except Exception as e:
            raw.append(f"HEAD {base} error: {type(e).__name__}: {e}")

        probe_paths = ["/", "/upload", "/api", "/test", "/debug", "/admin", "/files", "/documents", "/data", "/webdav", "/dav"]
        for method in DANGEROUS_METHODS:
            for i, path in enumerate(probe_paths[:10]):
                url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
                try:
                    r = http_request(
                        s,
                        method,
                        url,
                        timeout=(self.config.connect_timeout, self.config.read_timeout),
                        max_redirects=self.config.max_redirects,
                        max_bytes=32 * 1024,
                        data=b"test",
                        headers={"Content-Type": "text/plain"},
                    )
                    raw.append(f"{method} {url} => {r.status_code} final={getattr(r,'url',url)}")
                    if r.status_code < 300:
                        allowed.append((method, url, r.status_code, "Request accepted"))
                    elif r.status_code in (401, 403):
                        allowed.append((method, url, r.status_code, "Protected by auth/ACL"))
                except Exception as e:
                    raw.append(f"{method} {url} error: {type(e).__name__}: {e}")
                if i < self.config.retries:
                    sleep_backoff(i)

        for method, url, code, why in allowed:
            if method == "TRACE" and code < 300:
                sev, conf = "HIGH", "high"
                reason = "Direct evidence: TRACE accepted."
            elif code < 300:
                sev, conf = "HIGH", "medium"
                reason = "Method accepted, impact depends on endpoint and auth."
            elif code in (401, 403):
                sev, conf = "LOW", "high"
                reason = "Endpoint exists but appears protected (401/403)."
            else:
                sev, conf = "MEDIUM", "low"
                reason = "Ambiguous behavior; manual validation recommended."

            res.add_finding(
                title=f"{method} method appears enabled",
                severity=sev,
                confidence=conf,
                risk="Potential XST / upload / overwrite / proxy abuse depending on method and endpoint.",
                evidence=f"{method} {url} => {code} ({why})",
                recommendation="Disable dangerous methods when not necessary (TRACE/PUT/DELETE/CONNECT) and restrict at the web server/reverse proxy.",
                confidence_reason=reason,
            )

        if res.findings:
            # Highest severity among findings
            res.severity = max((f.severity for f in res.findings), default="INFO")
            res.confidence = max((f.confidence for f in res.findings), default="medium")

        res.evidence = safe_truncate("\n".join(raw), 10000)
        res.metadata["base_url"] = base
        return res
