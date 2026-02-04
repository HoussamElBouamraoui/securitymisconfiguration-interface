#!/usr/bin/env python3
"""
🍪 Analyse Cookies ULTRA-AGRESSIF v3.0 - Mode MAXIMUM
Intégration complète avec le moteur amélioré d'InjectionHunter
"""

import time
from colorama import Fore, Style

class CookiesAnalyzerV3:
    def __init__(self, engine):
        self.engine = engine
    
    def scan(self, aggressive=False):
        print(f"\n{Fore.YELLOW}[🍪 ANALYSE COOKIES ULTRA-AGRESSIF v3.0] {Style.RESET_ALL}")
        print(f"    {Fore.RED}[MODE MAXIMUM] {Style.RESET_ALL}Détection cookies et sessions ULTRA-avancée\n")
        
        results = []
        
        # Utiliser les cookies découverts par le moteur
        all_cookies = self.engine.get_all_cookies()
        session_variations = self.engine.get_session_variations()
        
        if all_cookies:
            print(f"    {Fore.GREEN}[+] {Style.RESET_ALL}🍪 {len(all_cookies)} cookies uniques découverts par le moteur\n")
            
            # Analyser chaque cookie découvert
            for cookie_key, cookie_data in all_cookies.items():
                print(f"    🍪 {Fore.CYAN}{cookie_data['name']}{Style.RESET_ALL}")
                print(f"    Valeur: {Fore.WHITE}{cookie_data['value'][:50]}{'...' if len(cookie_data['value']) > 50 else ''}{Style.RESET_ALL}")
                print(f"    Stratégie: {Fore.YELLOW}{cookie_data['strategy']}{Style.RESET_ALL}")
                
                # Attributs détaillés
                if 'attributes' in cookie_data:
                    print(f"    {Fore.WHITE}Attributs détectés:{Style.RESET_ALL}")
                    for attr in cookie_data['attributes']:
                        print(f"      • {attr.strip()}")
                
                if 'type' in cookie_data and cookie_data['type'] == 'session':
                    print(f"    Type: {Fore.GREEN}Cookie de session{Style.RESET_ALL}")
                    if 'domain' in cookie_data:
                        print(f"    Domaine: {cookie_data['domain'] or 'courant'}")
                    if 'path' in cookie_data:
                        print(f"    Path: {cookie_data['path']}")
                    if 'secure' in cookie_data:
                        secure_status = f"{Fore.GREEN}✅ HTTPS uniquement{Style.RESET_ALL}" if cookie_data['secure'] else f"{Fore.RED}❌ Transmis en HTTP/HTTPS{Style.RESET_ALL}"
                        print(f"    Secure: {secure_status}")
                    if 'expires' in cookie_data:
                        if cookie_data['expires']:
                            import time
                            expiry_time = time.strftime('%a, %d-%b-%Y %H:%M:%S GMT', time.gmtime(cookie_data['expires']))
                            print(f"    Expiration: {expiry_time}")
                        else:
                            print(f"    Expiration: {Fore.YELLOW}Session{Style.RESET_ALL}")
                
                print()
                
                results.append({
                    'type': 'cookie',
                    'name': cookie_data['name'],
                    'value': cookie_data['value'],
                    'strategy': cookie_data['strategy'],
                    'cookie_type': cookie_data.get('type', 'standard'),
                    'secure': cookie_data.get('secure', False),
                    'domain': cookie_data.get('domain', ''),
                    'path': cookie_data.get('path', '/'),
                })
        
        # Analyser les variations de sessions
        if session_variations:
            print(f"    {Fore.GREEN}[+] {Style.RESET_ALL}🔄 {len(session_variations)} variations de sessions détectées\n")
            
            unique_sessions = {}
            for session in session_variations:
                session_id = session['session_id']
                if session_id not in unique_sessions:
                    unique_sessions[session_id] = []
                unique_sessions[session_id].append(session)
            
            print(f"    {Fore.CYAN}[SESSIONS UNIQUES] {Style.RESET_ALL}{len(unique_sessions)} sessions PHP différentes:")
            for i, (session_id, variations) in enumerate(unique_sessions.items(), 1):
                print(f"      {i}. PHPSESSID: {Fore.YELLOW}{session_id[:20]}...{Style.RESET_ALL}")
                print(f"         Variations: {len(variations)} stratégies différentes")
                for var in variations:
                    print(f"           • {var['strategy']} - {var['user_agent'][:30]}...")
                print()
                
                results.append({
                    'type': 'session_variation',
                    'session_id': session_id,
                    'variations_count': len(variations),
                    'strategies': [v['strategy'] for v in variations]
                })
        
        # Scan complémentaire agressif si demandé
        if aggressive:
            print(f"    {Fore.RED}[SCAN COMPLÉMENTAIRE] {Style.RESET_ALL}Recherche supplémentaire...")
            self._complementary_scan(results)
        
        # Résumé final
        total_cookies = len([r for r in results if r['type'] == 'cookie'])
        total_sessions = len([r for r in results if r['type'] == 'session_variation'])
        
        print(f"    {Fore.GREEN}[✅ RÉSUMÉ] {Style.RESET_ALL}")
        print(f"    • {total_cookies} cookies uniques détectés")
        print(f"    • {total_sessions} sessions PHP différentes")
        print(f"    • {total_cookies + total_sessions} éléments de suivi total")
        
        return results
    
    def _complementary_scan(self, results):
        """Scan complémentaire pour maximiser la détection"""
        try:
            # Scanner avec différentes méthodes HTTP
            methods = ['GET', 'POST', 'HEAD', 'OPTIONS']
            
            for method in methods:
                try:
                    if method == 'POST':
                        resp = self.engine.session.post(self.engine.url, data={}, timeout=3)
                    elif method == 'HEAD':
                        resp = self.engine.session.head(self.engine.url, timeout=3)
                    elif method == 'OPTIONS':
                        resp = self.engine.session.options(self.engine.url, timeout=3)
                    else:
                        resp = self.engine.session.get(self.engine.url, timeout=3)
                    
                    # Vérifier les nouveaux cookies
                    for cookie in resp.cookies:
                        cookie_key = f"{method}_{cookie.name}_{str(cookie.value)[:20]}"
                        # Ajouter aux résultats si nouveau
                        existing = [r for r in results if r['name'] == cookie.name and r['value'] == str(cookie.value)]
                        if not existing:
                            results.append({
                                'type': 'cookie',
                                'name': cookie.name,
                                'value': str(cookie.value),
                                'strategy': f'{method}_method',
                                'cookie_type': 'complementary',
                                'secure': cookie.secure,
                                'domain': cookie.domain,
                                'path': cookie.path,
                            })
                
                except:
                    continue
                    
        except Exception as e:
            print(f"    {Fore.YELLOW}[!] {Style.RESET_ALL}Erreur scan complémentaire: {e}")
