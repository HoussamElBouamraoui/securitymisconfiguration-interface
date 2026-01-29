"""Detection of insecure cloud storage configurations (S3, Azure Blob, GCS).

Based on OWASP A02:2025 Scenario #4:
"A cloud service provider defaults to having sharing permissions open to the Internet"
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core.base_check import BaseCheck
from ..core.utils import http_request, normalize_target, requests_session, safe_truncate


# Common cloud storage patterns
CLOUD_STORAGE_PATTERNS = [
    # AWS S3
    (r'https?://([a-z0-9.-]+\.)?s3[.-]([a-z0-9-]+\.)?amazonaws\.com', "AWS S3"),
    (r'https?://s3\.amazonaws\.com/[a-z0-9.-]+', "AWS S3"),

    # Azure Blob Storage
    (r'https?://([a-z0-9]+)\.blob\.core\.windows\.net', "Azure Blob"),

    # Google Cloud Storage
    (r'https?://storage\.googleapis\.com/[a-z0-9.-]+', "Google Cloud Storage"),
    (r'https?://([a-z0-9.-]+)\.storage\.googleapis\.com', "Google Cloud Storage"),

    # DigitalOcean Spaces
    (r'https?://([a-z0-9.-]+)\.digitaloceanspaces\.com', "DigitalOcean Spaces"),

    # Backblaze B2
    (r'https?://([a-z0-9.-]+)\.backblazeb2\.com', "Backblaze B2"),
]

# Files that might reveal cloud storage URLs
CLOUD_URL_SOURCES = [
    "/",
    "/index.html",
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/config.js",
    "/app.js",
]


class CloudStoragePermissions(BaseCheck):
    """Detect publicly accessible cloud storage buckets.

    CWE-16: Configuration
    CWE-15: External Control of System or Configuration Setting

    Based on OWASP A02:2025 Scenario #4.
    """

    scan_type = "A02_Cloud_Storage_Permissions"

    def run(self, target: str):
        res = self._result(target)
        base = normalize_target(target)
        s = requests_session(self.config.user_agent)

        cloud_findings = []
        raw = []

        # Extract cloud storage URLs from various sources
        cloud_urls = set()

        for source in CLOUD_URL_SOURCES[:5]:
            url = base.rstrip("/") + source
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
                    # Search for cloud storage URLs in response
                    for pattern, provider in CLOUD_STORAGE_PATTERNS:
                        matches = re.findall(pattern, r.text, re.IGNORECASE)
                        for match in matches:
                            # Reconstruct full URL
                            full_match = re.search(pattern, r.text, re.IGNORECASE)
                            if full_match:
                                cloud_url = full_match.group(0)
                                cloud_urls.add((cloud_url, provider))

            except Exception as e:
                raw.append(f"GET {url} error: {type(e).__name__}")

        # Test each discovered cloud storage URL
        for cloud_url, provider in cloud_urls:
            try:
                # Try to access the bucket/container
                r = http_request(
                    s,
                    "GET",
                    cloud_url,
                    timeout=(self.config.connect_timeout, self.config.read_timeout),
                    max_redirects=0,  # Don't follow redirects
                )

                raw.append(f"GET {cloud_url} [{provider}] => {r.status_code}")

                # Check if publicly accessible
                is_public = False
                evidence_type = ""

                if r.status_code == 200:
                    body = r.text.lower()

                    # S3 specific checks
                    if "s3" in provider.lower():
                        if "<listbucketresult" in body or "<contents>" in body:
                            is_public = True
                            evidence_type = "S3 bucket listing accessible"

                    # Azure Blob specific checks
                    elif "azure" in provider.lower():
                        if "<enumeration" in body or "<blob>" in body:
                            is_public = True
                            evidence_type = "Azure Blob container listing accessible"

                    # GCS specific checks
                    elif "google" in provider.lower():
                        if '"items"' in body or '"kind": "storage#' in body:
                            is_public = True
                            evidence_type = "GCS bucket listing accessible"

                    # Generic check: if we got content, it's publicly accessible
                    elif len(r.content) > 0:
                        is_public = True
                        evidence_type = f"{provider} publicly accessible"

                if is_public:
                    cloud_findings.append({
                        "url": cloud_url,
                        "provider": provider,
                        "status": r.status_code,
                        "evidence": evidence_type,
                        "size": len(r.content)
                    })

            except Exception as e:
                raw.append(f"GET {cloud_url} error: {type(e).__name__}")

        # Also try to guess common bucket names based on domain
        parsed = urlparse(base)
        domain = parsed.netloc.replace("www.", "").split(".")[0]

        # Common S3 bucket naming patterns
        bucket_guesses = [
            f"https://{domain}.s3.amazonaws.com",
            f"https://s3.amazonaws.com/{domain}",
            f"https://{domain}-bucket.s3.amazonaws.com",
            f"https://{domain}-assets.s3.amazonaws.com",
            f"https://{domain}-static.s3.amazonaws.com",
            f"https://{domain}-uploads.s3.amazonaws.com",
        ]

        for bucket_url in bucket_guesses[:5]:
            try:
                r = http_request(
                    s,
                    "GET",
                    bucket_url,
                    timeout=(self.config.connect_timeout, self.config.read_timeout),
                    max_redirects=0,
                )

                raw.append(f"GET {bucket_url} [Guess] => {r.status_code}")

                if r.status_code == 200:
                    body = r.text.lower()
                    if "<listbucketresult" in body or "<contents>" in body:
                        cloud_findings.append({
                            "url": bucket_url,
                            "provider": "AWS S3",
                            "status": r.status_code,
                            "evidence": "S3 bucket found via naming pattern guess",
                            "size": len(r.content)
                        })

            except Exception:
                pass  # Silently continue

        # Create findings
        if cloud_findings:
            for finding in cloud_findings:
                severity = "CRITICAL" if finding["status"] == 200 else "HIGH"

                res.add_finding(
                    title=f"Publicly accessible {finding['provider']} storage (CWE-16)",
                    severity=severity,
                    confidence="high",
                    risk=f"Cloud storage is publicly accessible, potentially exposing sensitive data. {finding['evidence']}",
                    evidence=f"{finding['url']} => {finding['status']} ({finding['size']} bytes)",
                    recommendation=f"Restrict {finding['provider']} permissions. Use bucket policies to deny public access. Enable access logging and monitoring.",
                    confidence_reason="Direct evidence: cloud storage accessible without authentication."
                )

            res.severity = "CRITICAL"
            res.confidence = "high"
            res.metadata["cloud_findings"] = cloud_findings
            res.metadata["owasp_scenario"] = "A02:2025 Scenario #4"

        res.evidence = safe_truncate("\n".join(raw), 10000)
        res.metadata["base_url"] = base
        res.metadata["buckets_tested"] = len(cloud_urls) + len(bucket_guesses)
        return res
