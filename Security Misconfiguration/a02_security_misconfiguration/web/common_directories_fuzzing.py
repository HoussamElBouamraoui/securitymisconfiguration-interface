"""Aggressive fuzzing of common directories and admin panels."""

from __future__ import annotations

from urllib.parse import urljoin

import concurrent.futures
import os

from ..core.base_check import BaseCheck
from ..core.utils import http_request, normalize_target, requests_session, safe_truncate


COMMON_PATHS = [
    # Admin panels
    "/admin/",
    "/administrator/",
    "/admin.php",
    "/admin/login",
    "/admin/dashboard",
    "/backend/",
    "/cpanel/",
    "/controlpanel/",
    "/manager/",
    "/webadmin/",

    # Authentication
    "/login",
    "/login.php",
    "/signin",
    "/auth/",
    "/authenticate/",

    # Debug/Dev endpoints
    "/debug/",
    "/test/",
    "/staging/",
    "/dev/",
    "/_debug/",
    "/console/",
    "/shell/",

    # Server info
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/server-info",
    "/status",

    # API endpoints
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/rest/",
    "/graphql",
    "/swagger/",
    "/swagger-ui/",
    "/swagger-ui.html",
    "/api-docs/",
    "/redoc/",

    # Monitoring
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/mappings",
    "/actuator/metrics",
    "/actuator/beans",
    "/actuator/configprops",
    "/metrics",
    "/health",
    "/healthz",
    "/prometheus",

    # CMS specific
    "/wp-admin/",
    "/wp-login.php",
    "/wp-content/",
    "/wordpress/",
    "/joomla/administrator/",
    "/drupal/",
    "/phpmyadmin/",
    "/pma/",

    # Config/sensitive
    "/.env",
    "/config/",
    "/.git/",
    "/.svn/",
    "/.well-known/",
    "/backup/",
    "/backups/",
    "/tmp/",
    "/temp/",
    "/uploads/",

    # Default pages
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]


class CommonDirectoriesFuzzing(BaseCheck):
    scan_type = "A02_Common_Directories_Fuzzing"

    def run(self, target: str):
        res = self._result(target)
        base = normalize_target(target)
        s = requests_session(self.config.user_agent)

        raw = []
        findings_count = 0

        paths = COMMON_PATHS[: self.config.web_max_paths]
        max_req = max(1, int(getattr(self.config, "web_max_requests", len(paths))))
        paths = paths[:max_req]

        # Concurrency: avoid fully serial fuzzing (too slow) while staying bounded.
        workers = max(4, min(32, (os.cpu_count() or 4) * 2))

        def _probe_one(path: str):
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            r = http_request(
                s,
                "GET",
                url,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                max_redirects=self.config.max_redirects,
                max_bytes=64 * 1024,
            )
            # Evidence enrichment (without storing full body)
            ct = (r.headers.get("Content-Type") or "").split(";")[0].strip()
            final_url = str(getattr(r, "url", url))
            return url, final_url, r.status_code, ct, len(r.content or b""), r

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(_probe_one, p): p for p in paths}
            for f in concurrent.futures.as_completed(futs):
                path = futs[f]
                try:
                    url, final_url, status, ct, blen, _resp = f.result()
                    raw.append(f"GET {url} => {status} ct={ct} bytes={blen} final={final_url}")

                    if status == 200:
                        sev, conf = "MEDIUM", "high"
                        reason = "Direct evidence: endpoint accessible (200)."
                        risk = "Exposed admin/debug endpoints increase attack surface."
                    elif status in (401, 403):
                        sev, conf = "LOW", "high"
                        reason = "Endpoint exists but appears protected (401/403)."
                        risk = "Protected endpoint still increases attack surface and should be restricted."
                    else:
                        continue

                    res.add_finding(
                        title="Interesting/common endpoint discovered",
                        severity=sev,
                        confidence=conf,
                        risk=risk,
                        evidence=f"GET {url} => {status} (final={final_url}, ct={ct}, bytes={blen})",
                        recommendation="Restrict access (VPN/allowlists), disable debug endpoints, and remove unused routes.",
                        confidence_reason=reason,
                    )
                    findings_count += 1
                except Exception as e:
                    raw.append(f"GET {path} error: {type(e).__name__}: {e}")

        if res.findings:
            res.severity = max((f.severity for f in res.findings), default="INFO")
            res.confidence = max((f.confidence for f in res.findings), default="medium")

        res.evidence = safe_truncate("\n".join(raw), 10000)
        res.metadata["base_url"] = base
        res.metadata["requests_sent"] = len(paths)
        res.metadata["workers"] = workers
        res.metadata["hits"] = findings_count
        return res
