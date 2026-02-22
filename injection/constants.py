#!/usr/bin/env python3
"""
OWASP Top 10 A05:2025 — Injection — Constantes et mapping CWE.
Référence: https://owasp.org/Top10/A05_2021-Injection/
37 CWEs mappés, 62k+ CVEs. Usage strictement autorisé.
"""

# OWASP A05:2025 — Injection
OWASP_A05_2025_ID = "A05:2025"
OWASP_A05_2025_TITLE = "Injection"

# CWE mappés (OWASP A05:2025)
CWE_SQL_INJECTION = "CWE-89"
CWE_OS_COMMAND_INJECTION = "CWE-78"
CWE_COMMAND_INJECTION = "CWE-77"
CWE_XSS = "CWE-79"
CWE_XSS_BASIC = "CWE-80"
CWE_XSS_SCRIPT_ATTR = "CWE-83"
CWE_LDAP_INJECTION = "CWE-90"
CWE_XPATH_INJECTION = "CWE-91"
CWE_CRLF_INJECTION = "CWE-93"
CWE_CODE_INJECTION = "CWE-94"
CWE_EVAL_INJECTION = "CWE-95"
CWE_STATIC_CODE_INJECTION = "CWE-96"
CWE_SSI_INJECTION = "CWE-97"
CWE_PHP_RFI = "CWE-98"
CWE_RESOURCE_INJECTION = "CWE-99"
CWE_IMPROPER_INPUT_VALIDATION = "CWE-20"
CWE_NEUTRALIZATION_SPECIAL_ELEMENTS = "CWE-74"
CWE_EQUIVALENT_SPECIAL_ELEMENTS = "CWE-76"
CWE_ARGUMENT_INJECTION = "CWE-88"
CWE_HTTP_RESPONSE_SPLITTING = "CWE-113"
CWE_XPATH_INJECTION_643 = "CWE-643"
CWE_EXPRESSION_LANGUAGE_INJECTION = "CWE-917"
CWE_HIBERNATE_SQL_INJECTION = "CWE-564"
CWE_SSRF = "CWE-610"
CWE_IDENTIFIER_INVALID_CHARS = "CWE-86"
CWE_HEADERS_SCRIPTING = "CWE-644"
CWE_UNSAFE_REFLECTION = "CWE-470"

# Mapping type vuln -> CWE principal
VULN_TYPE_TO_CWE = {
    "sqli": CWE_SQL_INJECTION,
    "xss": CWE_XSS,
    "cmdi": CWE_OS_COMMAND_INJECTION,
    "lfi": CWE_PHP_RFI,
    "ldap": CWE_LDAP_INJECTION,
    "xpath": CWE_XPATH_INJECTION,
    "orm": CWE_HIBERNATE_SQL_INJECTION,
    "template_injection": CWE_CODE_INJECTION,
    "template_injection_rce": CWE_CODE_INJECTION,
    "ssrf": CWE_SSRF,
    "ssrf_port": CWE_SSRF,
    "deserialization": CWE_CODE_INJECTION,
    "deserialization_rce": CWE_CODE_INJECTION,
    "websocket_injection": CWE_XSS,
    "websocket_rce": CWE_OS_COMMAND_INJECTION,
    "config_violation": CWE_IMPROPER_INPUT_VALIDATION,
    "asvs_violation": CWE_IMPROPER_INPUT_VALIDATION,
    "cookie": CWE_HEADERS_SCRIPTING,
    "session_variation": CWE_IMPROPER_INPUT_VALIDATION,
    "form": CWE_IMPROPER_INPUT_VALIDATION,
    "admin": "INFO",
    "cms": "INFO",
}

# Paramètres par défaut pour tests sans paramètres URL (headers, body, noms courants)
DEFAULT_INJECTION_PARAM_NAMES = [
    "id", "page", "file", "path", "url", "uri", "redirect", "dest", "target",
    "q", "query", "search", "name", "template", "callback", "ref", "data",
    "input", "cmd", "exec", "command", "req", "request", "content", "body",
    "payload", "value", "val", "v", "key", "k", "filter", "sort", "order",
    "limit", "offset", "format", "type", "action", "do", "method", "callback",
]

# Références OWASP
OWASP_REFERENCES = [
    "OWASP Proactive Controls: Secure Database Access",
    "OWASP ASVS: V5 Input Validation and Encoding",
    "OWASP Testing Guide: SQL Injection, Command Injection, ORM Injection",
    "OWASP Cheat Sheet: Injection Prevention",
    "OWASP Cheat Sheet: SQL Injection Prevention",
]
