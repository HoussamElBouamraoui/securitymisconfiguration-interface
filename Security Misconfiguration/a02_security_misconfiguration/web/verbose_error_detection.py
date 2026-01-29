"""Provoke controlled errors and look for verbose error disclosures."""

from __future__ import annotations

import random
import string
from urllib.parse import urljoin

from ..core.base_check import BaseCheck
from ..core.utils import http_request, is_verbose_error, normalize_target, requests_session, safe_truncate


class VerboseErrorDetection(BaseCheck):
    scan_type = "A02_Verbose_Error_Detection"

    def run(self, target: str):
        res = self._result(target)
        base = normalize_target(target)
        s = requests_session(self.config.user_agent)

        token = "".join(random.choice(string.ascii_letters) for _ in range(12))
        candidates = [
            f"/__does_not_exist__{token}",
            f"/%0d%0a{token}",
            f"/?q=%27%22%3C%3E{token}",
        ]

        raw = []
        verbose = []
        for path in candidates:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = http_request(
                    s,
                    "GET",
                    url,
                    timeout=(self.config.connect_timeout, self.config.read_timeout),
                    max_redirects=self.config.max_redirects,
                )
                body = r.text[:40000]
                raw.append(f"GET {url} => {r.status_code} len={len(body)}")
                if r.status_code >= 500 and is_verbose_error(body):
                    verbose.append((url, r.status_code))
            except Exception as e:
                raw.append(f"GET {url} error: {type(e).__name__}: {e}")

        if verbose:
            res.severity = "HIGH"
            res.confidence = "medium"
            res.add_finding(
                title="Verbose error pages (stack traces)",
                severity="HIGH",
                confidence="medium",
                risk="Error pages may leak stack traces, frameworks and internal paths, enabling targeted attacks.",
                evidence=safe_truncate("\n".join([f"{u} => {c}" for u, c in verbose]), 4000),
                recommendation="Disable debug mode, configure generic error pages, and avoid leaking stack traces in production.",
                confidence_reason="Heuristic detection based on common stack-trace patterns in 5xx responses; manual validation recommended.",
            )
            res.metadata["verbose_error_urls"] = [u for u, _ in verbose]

        res.evidence = safe_truncate("\n".join(raw), 10000)
        res.metadata["base_url"] = base
        return res
