"""Detect directory listing by probing common directory paths."""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.base_check import BaseCheck
from ..core.utils import (
    http_request,
    looks_like_directory_listing,
    normalize_target,
    requests_session,
    safe_truncate,
)


COMMON_DIRS = [
    "/",
    "/static/",
    "/assets/",
    "/images/",
    "/uploads/",
    "/download/",
    "/public/",
    "/backup/",
]


class DirectoryListingDetection(BaseCheck):
    scan_type = "A02_Directory_Listing_Detection"

    def run(self, target: str):
        res = self._result(target)
        base = normalize_target(target)
        s = requests_session(self.config.user_agent)

        hits = []
        raw = []
        for path in COMMON_DIRS[: self.config.web_max_paths]:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                r = http_request(
                    s,
                    "GET",
                    url,
                    timeout=(self.config.connect_timeout, self.config.read_timeout),
                    max_redirects=self.config.max_redirects,
                    max_bytes=128 * 1024,
                )
                final_url = str(getattr(r, "url", url))
                raw.append(f"GET {url} => {r.status_code} final={final_url}")
                body = (r.text or "")[:20000]
                if r.status_code == 200 and looks_like_directory_listing(body):
                    hits.append(f"{final_url} (from {url})")
            except Exception as e:
                raw.append(f"GET {url} error: {type(e).__name__}: {e}")

        if hits:
            res.severity = "HIGH"
            res.confidence = "high"
            res.add_finding(
                title="Directory listing enabled",
                severity="HIGH",
                confidence="high",
                risk="Directory listing exposes file names and may leak sensitive data or backups.",
                evidence=safe_truncate("\n".join(hits), 4000),
                recommendation="Disable auto-index/directory listing on the web server and restrict access to static directories.",
                confidence_reason="Direct evidence: directory listing signature detected in HTTP response.",
            )
            res.metadata["directory_listing_urls"] = hits

        res.evidence = safe_truncate("\n".join(raw), 10000)
        res.metadata["base_url"] = base
        return res
