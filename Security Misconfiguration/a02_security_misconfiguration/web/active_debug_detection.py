"""Detection of debug code and insecure debug configurations.

CWE-489: Active Debug Code
CWE-11: ASP.NET Misconfiguration: Creating Debug Binary
"""

from __future__ import annotations

from ..core.base_check import BaseCheck
from ..core.utils import http_request, normalize_target, requests_session, safe_truncate


# Debug indicators in responses
DEBUG_PATTERNS = [
    # Debug mode enabled
    "debug=true",
    "debug mode",
    "debugging enabled",
    "debug: true",

    # ASP.NET debug
    "compilation debug=\"true\"",
    "<compilation debug=",
    "asp.net_sessionid",

    # Framework debug
    "app_debug = true",
    "app.debug = true",
    "debug_mode=on",
    "env = development",
    "environment: development",

    # Stack traces (debug indicators)
    "traceback",
    "stack trace",
    "debug backtrace",

    # Debug headers
    "x-debug",
    "x-debug-token",
    "x-symfony-debug",

    # Console outputs
    "console.log(",
    "var_dump(",
    "print_r(",
    "dd(",  # Laravel dump
]

# Debug endpoints
DEBUG_ENDPOINTS = [
    "/_debug",
    "/_profiler",
    "/debug",
    "/debug/",
    "/debug/default/view",
    "/.well-known/debug",
    "/telescope",  # Laravel
    "/clockwork",  # PHP
    "/_wdt",  # Symfony
]


class ActiveDebugDetection(BaseCheck):
    """Detect active debug code and debug mode enabled.

    CWE-489: Active Debug Code
    CWE-11: ASP.NET Misconfiguration: Creating Debug Binary
    """

    scan_type = "A02_Active_Debug_Detection"

    def run(self, target: str):
        res = self._result(target)
        base = normalize_target(target)
        s = requests_session(self.config.user_agent)

        debug_indicators = []
        raw = []

        # Test main page for debug indicators
        try:
            r = http_request(
                s,
                "GET",
                base,
                timeout=(self.config.connect_timeout, self.config.read_timeout),
                max_redirects=self.config.max_redirects,
            )

            body = r.text.lower()
            headers = {k.lower(): v for k, v in r.headers.items()}

            # Check response body for debug patterns
            found_patterns = []
            for pattern in DEBUG_PATTERNS:
                if pattern.lower() in body:
                    found_patterns.append(pattern)

            if found_patterns:
                debug_indicators.append({
                    "location": "response_body",
                    "url": base,
                    "patterns": found_patterns[:5],  # Limit to first 5
                    "cwe": "CWE-489"
                })

            # Check headers for debug indicators
            debug_headers = []
            for header, value in headers.items():
                if "debug" in header or "trace" in header:
                    debug_headers.append(f"{header}: {value}")

            if debug_headers:
                debug_indicators.append({
                    "location": "http_headers",
                    "url": base,
                    "headers": debug_headers,
                    "cwe": "CWE-489"
                })

            # Check for ASP.NET debug
            if "compilation debug=\"true\"" in body or "<compilation debug=" in body:
                debug_indicators.append({
                    "location": "aspnet_config",
                    "url": base,
                    "evidence": "ASP.NET debug compilation enabled",
                    "cwe": "CWE-11"
                })

            raw.append(f"GET {base} => {r.status_code}")

        except Exception as e:
            raw.append(f"GET {base} error: {type(e).__name__}: {e}")

        # Test debug endpoints
        for endpoint in DEBUG_ENDPOINTS[:10]:
            url = base.rstrip("/") + endpoint
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

                    # Check if it's actually a debug endpoint
                    if any(word in body for word in ["debug", "profiler", "trace", "dump", "log"]):
                        debug_indicators.append({
                            "location": "debug_endpoint",
                            "url": url,
                            "status": r.status_code,
                            "cwe": "CWE-489"
                        })

            except Exception as e:
                raw.append(f"GET {url} error: {type(e).__name__}")

        # Create findings
        if debug_indicators:
            # Group by type
            body_debug = [i for i in debug_indicators if i["location"] == "response_body"]
            header_debug = [i for i in debug_indicators if i["location"] == "http_headers"]
            aspnet_debug = [i for i in debug_indicators if i["location"] == "aspnet_config"]
            endpoint_debug = [i for i in debug_indicators if i["location"] == "debug_endpoint"]

            if body_debug or header_debug:
                patterns = []
                if body_debug:
                    patterns.extend(body_debug[0].get("patterns", []))
                if header_debug:
                    patterns.extend(header_debug[0].get("headers", []))

                res.add_finding(
                    title="Active debug code detected (CWE-489)",
                    severity="HIGH",
                    confidence="high",
                    risk="Debug code in production exposes sensitive information, internal paths, variables, and may allow code execution.",
                    evidence=f"Debug indicators found: {', '.join(patterns[:10])}",
                    recommendation="Disable debug mode in production. Set debug=false in all configuration files. Remove debug code before deployment.",
                    confidence_reason="Direct evidence of debug mode enabled in production environment."
                )

            if aspnet_debug:
                res.add_finding(
                    title="ASP.NET debug compilation enabled (CWE-11)",
                    severity="HIGH",
                    confidence="high",
                    risk="Debug binaries contain additional information and may perform slower. Attackers can extract more information from stack traces.",
                    evidence="ASP.NET compilation debug=\"true\" detected in web.config",
                    recommendation="Set <compilation debug=\"false\"> in web.config for production.",
                    confidence_reason="Direct evidence from configuration file."
                )

            if endpoint_debug:
                endpoints = [i["url"] for i in endpoint_debug]
                res.add_finding(
                    title="Debug endpoints exposed (CWE-489)",
                    severity="HIGH",
                    confidence="high",
                    risk="Debug endpoints expose application internals, profiling data, logs, and may allow arbitrary code execution.",
                    evidence=f"Accessible debug endpoints: {', '.join(endpoints[:5])}",
                    recommendation="Disable or restrict access to debug endpoints in production (IP whitelist, authentication).",
                    confidence_reason="Debug endpoints accessible without authentication."
                )

            res.severity = "HIGH"
            res.confidence = "high"
            res.metadata["debug_indicators"] = debug_indicators

        res.evidence = safe_truncate("\n".join(raw), 10000)
        res.metadata["base_url"] = base
        return res
