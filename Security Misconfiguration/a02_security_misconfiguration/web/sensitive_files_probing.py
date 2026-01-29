"""Probe for common sensitive files (.env, .git, backups, configs)."""

from __future__ import annotations

from urllib.parse import urljoin

from ..core.base_check import BaseCheck
from ..core.utils import http_request, normalize_target, requests_session, safe_truncate


SENSITIVE_PATHS = [
    # Environment & Config
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.backup",
    "/.env.old",
    "/config.php",
    "/config.inc.php",
    "/config.php~",
    "/configuration.php",
    "/settings.php",
    "/database.yml",
    "/database.php",
    "/db.php",
    "/web.config",
    "/app.config",
    "/application.properties",
    "/application.yml",

    # Version Control
    "/.git/config",
    "/.git/HEAD",
    "/.git/index",
    "/.git/logs/HEAD",
    "/.gitignore",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/",

    # Backups
    "/backup.zip",
    "/backup.tar.gz",
    "/backup.sql",
    "/backup.tar",
    "/site-backup.zip",
    "/website.zip",
    "/db_backup.sql",
    "/dump.sql",
    "/database.sql",
    "/backup/",
    "/.backup",
    "/old/",

    # Temporary files
    "/~",
    "/.bak",
    "/.swp",
    "/.save",
    "/config.php.bak",
    "/index.php.bak",
    "/config.php.old",
    "/config.php.save",

    # Package managers
    "/composer.json",
    "/composer.lock",
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",

    # Documentation
    "/README.md",
    "/CHANGELOG.md",
    "/TODO",
    "/TODO.txt",
    "/INSTALL",
    "/INSTALL.txt",

    # API specs
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs.json",

    # System files
    "/.DS_Store",
    "/Thumbs.db",
    "/desktop.ini",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",

    # Logs
    "/error_log",
    "/error.log",
    "/access.log",
    "/debug.log",
    "/app.log",
    "/application.log",

    # Keys & Certs
    "/id_rsa",
    "/id_rsa.pub",
    "/.ssh/id_rsa",
    "/server.key",
    "/privatekey.pem",
    "/certificate.crt",
]


class SensitiveFilesProbing(BaseCheck):
    scan_type = "A02_Sensitive_Files_Probing"

    def run(self, target: str):
        res = self._result(target)
        base = normalize_target(target)
        s = requests_session(self.config.user_agent)

        hits = []
        raw = []

        def _looks_like_false_positive(path: str, status: int, ct: str, body_prefix: bytes) -> bool:
            # Common "soft 404" / SPA fallback patterns
            if status != 200:
                return True
            c = (ct or "").lower()
            if "text/html" in c and path.lower().endswith((".zip", ".sql", ".tar", ".gz", ".pem", ".key", ".crt")):
                # Download endpoints most likely shouldn't return HTML
                return False
            prefix = body_prefix.lower()
            if b"<html" in prefix or b"<!doctype" in prefix:
                # Could be a generic app page; treat as suspicious only for a few paths.
                return path in {"/.env", "/.git/config", "/web.config", "/.htpasswd"}
            if prefix.strip() in {b"", b"not found", b"404"}:
                return True
            return False

        for path in SENSITIVE_PATHS[: self.config.web_max_paths]:
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
                ct = (r.headers.get("Content-Type") or "").split(";")[0].strip()
                final_url = str(getattr(r, "url", url))
                body_prefix = (r.content or b"")[:2048]
                raw.append(f"GET {url} => {r.status_code} ct={ct} bytes={len(r.content or b'')} final={final_url}")

                if r.status_code == 200 and len(r.content or b"") > 0:
                    if _looks_like_false_positive(path, r.status_code, ct, body_prefix):
                        continue
                    hits.append(f"{url} (ct={ct}, bytes~{len(r.content or b'')}, final={final_url})")
            except Exception as e:
                raw.append(f"GET {url} error: {type(e).__name__}: {e}")

        if hits:
            res.severity = "CRITICAL"
            res.confidence = "high"
            res.add_finding(
                title="Sensitive files exposed",
                severity="CRITICAL",
                confidence="high",
                risk="Direct exposure of secrets/configuration/backups may lead to full compromise.",
                evidence=safe_truncate("\n".join(hits), 6000),
                recommendation="Remove sensitive files from the web root, restrict access, and rotate potentially leaked secrets.",
                confidence_reason="Direct evidence: HTTP 200 with non-empty response for known sensitive paths (heuristics used to reduce soft-404 false positives).",
            )
            res.metadata["sensitive_hits"] = hits

        res.evidence = safe_truncate("\n".join(raw), 10000)
        res.metadata["base_url"] = base
        return res
