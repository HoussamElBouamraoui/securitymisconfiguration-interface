#!/usr/bin/env python3
"""
💉 INJECTIONHUNTER ULTRA-AGRESSIF v3.0 — OWASP A05:2025 COMPLET
Détection + Exploitation Maximale de TOUTES les vulnérabilités d'injection
"""

import argparse
import sys
import time
from colorama import Fore, Style, init
init(autoreset=True)

# Core
from core.engine import InjectionEngine
from core.detector import AdvancedDetector

# Modules offensifs (intégration de tes scripts)
from modules.sqli_blind import SQLIBlind
from modules.xss_polyglot import XSSPolyglot
from modules.cmdi_rce import CMDIRCE
from modules.lfi_traversal import LFITraversal
from modules.ldap_injection import LDAPInjection
from modules.xpath_injection import XPathInjection
from modules.orm_injection import ORMInjection
from modules.forms_scanner import FormsScanner
from modules.admin_finder import AdminFinder
from modules.cms_detector import CMSDetector
from modules.cookies_analyzer_v3 import CookiesAnalyzerV3

def banner():
    print(f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════════════════╗
{Fore.RED}║{Fore.YELLOW}  💀 INJECTIONHUNTER v3.0 ULTRA-AGRESSIF — OWASP A05:2025 COMPLET     {Fore.RED}    ║
{Fore.RED}║{Fore.GREEN}  TOUTES les vulnérabilités d'injection — Détection + Exploitation MAX  {Fore.RED}  ║
{Fore.RED}║{Fore.CYAN}  ⚠️  Usage STRICTEMENT autorisé sur sites avec consentement écrit     {Fore.RED}    ║
{Fore.RED}╚══════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
""")

def tool_info():
    print(f"""
{Fore.CYAN}{'='*70}{Style.RESET_ALL}
{Fore.YELLOW}[🎯 INJECTIONHUNTER - PRÉSENTATION]{Style.RESET_ALL}
{Fore.CYAN}{'='*70}{Style.RESET_ALL}

{Fore.GREEN}📋 DESCRIPTION COMPLÈTE{Style.RESET_ALL}
InjectionHunter v3.0 est un scanner de sécurité professionnel conçu pour 
détecter et analyser les vulnérabilités d'injection selon les standards 
OWASP A05:2025.

{Fore.GREEN}🔍 CAPACITÉS DE DÉTECTION{Style.RESET_ALL}
• {Fore.RED}SQL Injection{Style.RESET_ALL} (Blind, Time-based, Error-based, Union, NoSQL)
• {Fore.MAGENTA}Cross-Site Scripting{Style.RESET_ALL} (Stored, Reflected, DOM-based, Polyglot)
• {Fore.YELLOW}Command Injection{Style.RESET_ALL} (RCE, Reverse Shell, Obfuscation)
• {Fore.BLUE}Local File Inclusion{Style.RESET_ALL} (Path Traversal, PHP Wrappers)
• {Fore.CYAN}LDAP Injection{Style.RESET_ALL} (Filter bypass, ObjectClass manipulation)
• {Fore.BLUE}XPath Injection{Style.RESET_ALL} (XML injection, XQuery exploitation)
• {Fore.GREEN}ORM Injection{Style.RESET_ALL} (Hibernate, SQLAlchemy, Doctrine)

{Fore.GREEN}🛡️ FONCTIONNALITÉS AVANCÉES{Style.RESET_ALL}
• {Fore.YELLOW}Mode ULTRA-AGRESSIF{Style.RESET_ALL} : Payloads polymorphiques + Évasion WAF
• {Fore.YELLOW}Multi-stratégies{Style.RESET_ALL} : 8 approches de détection différentes
• {Fore.YELLOW}User-Agents rotation{Style.RESET_ALL} : Windows, Mac, Linux, Mobile émulation
• {Fore.YELLOW}Cookies analysis{Style.RESET_ALL} : Détection avancée + Session tracking
• {Fore.YELLOW}Forms scanning{Style.RESET_ALL} : Analyse complète des formulaires web
• {Fore.YELLOW}Admin discovery{Style.RESET_ALL} : Recherche de panneaux d'administration
• {Fore.YELLOW}CMS detection{Style.RESET_ALL} : Identification des systèmes de gestion
• {Fore.YELLOW}Exfiltration server{Style.RESET_ALL} : Capture automatique des données volées

{Fore.GREEN}🎯 TECHNIQUES D'ATTAQUE{Style.RESET_ALL}
• {Fore.RED}Payloads avancés{Style.RESET_ALL} : 500+ charges utiles spécialisées
• {Fore.RED}WAF Evasion{Style.RESET_ALL} : Contournement des firewalls applicatifs
• {Fore.RED}Polymorphic encoding{Style.RESET_ALL} : Évasion des systèmes de détection
• {Fore.RED}Multi-context analysis{Style.RESET_ALL} : Analyse comportementale intelligente
• {Fore.RED}False-positive filtering{Style.RESET_ALL} : Réduction des faux positifs

{Fore.GREEN}📊 RAPPORTS PROFESSIONNELS{Style.RESET_ALL}
• {Fore.YELLOW}Rapports HTML{Style.RESET_ALL} : Export professionnel pour les clients
• {Fore.YELLOW}Statistiques détaillées{Style.RESET_ALL} : CWE, CVSS, recommandations
• {Fore.YELLOW}Preuves d'exploitation{Style.RESET_ALL} : URLs et payloads validés
• {Fore.YELLOW}Timeline d'attaque{Style.RESET_ALL} : Chronologie des vulnérabilités

{Fore.GREEN}⚡ PERFORMANCE{Style.RESET_ALL}
• {Fore.YELLOW}Scan multi-threaded{Style.RESET_ALL} : Parallélisation des requêtes
• {Fore.YELLOW}Timeouts adaptatifs{Style.RESET_ALL} : Optimisation selon la cible
• {Fore.YELLOW}Cache intelligent{Style.RESET_ALL} : Évite les requêtes redondantes
• {Fore.YELLOW}Mode furtif{Style.RESET_ALL} : Analyse discrète possible

{Fore.GREEN}🔐 SÉCURITÉ ET ÉTHIQUE{Style.RESET_ALL}
Cet outil est développé pour des tests de sécurité autorisés uniquement.
Toute utilisation non autorisée est strictement interdite et illégale.

{Fore.CYAN}{'='*70}{Style.RESET_ALL}
""")

def ethical_check():
    print(f"{Fore.GREEN}[✅] {Style.RESET_ALL}Usage éthique confirmé automatiquement")
    print(f"{Fore.GREEN}[✅] {Style.RESET_ALL}Scanner prêt pour l'analyse de sécurité autorisée\n")

def main():
    banner()
    tool_info()
    ethical_check()
    
    parser = argparse.ArgumentParser(description="Scanner OWASP A05:2025 ULTRA-AGRESSIF")
    parser.add_argument("-u", "--url", required=True, help="URL cible (ex: https://site.com ou https://site.com/page?id=1)")
    parser.add_argument("-m", "--modules", default="all", 
                        help="Modules: sqli,xss,cmdi,lfi,ldap,xpath,orm,forms,admin,cms,cookies (défaut: all)")
    parser.add_argument("--attacker-url", help="URL publique attaquant (ex: https://abc123.ngrok.io)")
    parser.add_argument("--stealth", action="store_true", help="Mode furtif - pas de serveur d'exfiltration XSS")
    parser.add_argument("--aggressive", action="store_true", help="Mode ULTRA-AGRESSIF (payloads polymorphiques + evasion WAF)")
    args = parser.parse_args()
    
    print(f"\n{Fore.CYAN}[TARGET] {Style.RESET_ALL}{args.url}")
    if args.attacker_url:
        print(f"{Fore.CYAN}[ATTACKER] {Style.RESET_ALL}{args.attacker_url}")
    elif args.stealth:
        print(f"{Fore.GREEN}[MODE] {Style.RESET_ALL}Furtif - Pas d'exfiltration XSS")
    
    engine = InjectionEngine(args.url, attacker_url=args.attacker_url, aggressive=args.aggressive, stealth=args.stealth)
    params = engine.discover_params()
    
    # Scanner flexible - accepte les URLs avec ou sans paramètres
    modules_without_params = ['forms', 'admin', 'cms', 'cookies']
    needs_params = not any(mod in args.modules.split(',') for mod in modules_without_params)
    
    if needs_params and not params:
        print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Aucun paramètre détecté dans l'URL")
        print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Seuls les modules suivants fonctionnent sans paramètres : forms, admin, cms, cookies")
        print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Pour les tests d'injection, ajoutez des paramètres (ex: ?id=1&test=2)")
        print(f"{Fore.GREEN}[✓] {Style.RESET_ALL}Continuation avec les modules compatibles...\n")
    
    if params:
        print(f"{Fore.GREEN}[✓] {Style.RESET_ALL}Paramètres détectés: {', '.join(params)}\n")
    else:
        print(f"{Fore.GREEN}[✓] {Style.RESET_ALL}Scan sans paramètres - modules compatibles uniquement\n")
    
    # Modules mapping
    modules_map = {
        'sqli': SQLIBlind,
        'xss': XSSPolyglot,
        'cmdi': CMDIRCE,
        'lfi': LFITraversal,
        'ldap': LDAPInjection,
        'xpath': XPathInjection,
        'orm': ORMInjection,
        'forms': FormsScanner,
        'admin': AdminFinder,
        'cms': CMSDetector,
        'cookies': CookiesAnalyzerV3,
    }
    
    all_vulns = []
    for mod_name in args.modules.split(','):
        if mod_name == 'all':
            for name, module_class in modules_map.items():
                print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[ {name.upper()} ]{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                if name in ['forms', 'admin', 'cms', 'cookies']:
                    module = module_class(engine)
                    vulns = module.scan(aggressive=args.aggressive)
                else:
                    # Vérifier si des paramètres sont disponibles pour les modules d'injection
                    if params:
                        module = module_class(engine, aggressive=args.aggressive)
                        vulns = module.scan(params)
                    else:
                        print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Module {name} ignoré - nécessite des paramètres URL")
                        vulns = []
                all_vulns.extend(vulns)
            break
        elif mod_name in modules_map:
            print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[ {mod_name.upper()} ]{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            if mod_name in ['forms', 'admin', 'cms', 'cookies']:
                module = modules_map[mod_name](engine)
                vulns = module.scan(aggressive=args.aggressive)
            else:
                # Vérifier si des paramètres sont disponibles pour les modules d'injection
                if params:
                    module = modules_map[mod_name](engine, aggressive=args.aggressive)
                    vulns = module.scan(params)
                else:
                    print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Module {mod_name} ignoré - nécessite des paramètres URL")
                    vulns = []
            all_vulns.extend(vulns)
    
    # Rapport final
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[ RAPPORT FINAL ULTRA-AGRESSIF ]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    if not all_vulns:
        print(f"\n{Fore.GREEN}[✓] {Style.RESET_ALL}Aucune vulnérabilité d'injection détectée\n")
    else:
        print(f"\n{Fore.RED}[!] {Style.RESET_ALL}{len(all_vulns)} vulnérabilité(s) détectée(s):\n")
        for i, v in enumerate(all_vulns, 1):
            color = {
                'sqli': Fore.RED,
                'xss': Fore.MAGENTA,
                'cmdi': Fore.YELLOW,
                'lfi': Fore.BLUE,
                'ldap': Fore.CYAN,
                'xpath': Fore.BLUE,
                'orm': Fore.GREEN,
                'form': Fore.WHITE,
                'admin': Fore.CYAN,
                'cms': Fore.GREEN,
                'cookie': Fore.YELLOW,
                'session_variation': Fore.CYAN
            }.get(v['type'], Fore.WHITE)
            
            # Affichage détaillé selon le type
            if v['type'] == 'cookie':
                print(f"{color}{i}. [COOKIE] {v.get('name', 'N/A')}{Style.RESET_ALL}")
                print(f"   Valeur: {v.get('value', 'N/A')[:50]}{'...' if len(v.get('value', '')) > 50 else ''}")
                print(f"   Stratégie: {v.get('strategy', 'N/A')}")
                print(f"   Type: {v.get('cookie_type', 'standard')}")
                if v.get('secure'):
                    print(f"   Secure: {'✅ HTTPS uniquement' if v['secure'] else '❌ Transmis en HTTP/HTTPS'}")
                if v.get('domain'):
                    print(f"   Domaine: {v['domain']}")
                if v.get('path'):
                    print(f"   Path: {v['path']}")
            elif v['type'] == 'session_variation':
                print(f"{color}{i}. [SESSION] {v.get('session_id', 'N/A')[:20]}...{Style.RESET_ALL}")
                print(f"   Variations: {v.get('variations_count', 0)} stratégies différentes")
                print(f"   Stratégies: {', '.join(v.get('strategies', []))}")
            else:
                print(f"{color}{i}. [{v['type'].upper()}] {v.get('param', v.get('path', v.get('name', 'N/A')))}{Style.RESET_ALL}")
                if 'payload' in v:
                    print(f"   Payload: {v['payload'][:80]}...")
                if 'evidence' in v:
                    print(f"   Preuve: {v['evidence']}")
                if 'url' in v:
                    print(f"   URL: {v['url']}")
            print()
    
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[✓] {Style.RESET_ALL}Scan terminé !\n")
    
    # Garder serveur actif pour XSS (seulement si pas mode furtif)
    if any(v['type'] == 'xss' for v in all_vulns) and not args.stealth:
        print(f"\n{Fore.YELLOW}[!] {Style.RESET_ALL}Serveur d'exfiltration actif — cookies volés apparaîtront en direct")
        print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Appuie sur Ctrl+C pour arrêter\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] {Style.RESET_ALL}Arrêt\n")
    
    engine.stop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] {Style.RESET_ALL}Scan interrompu\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}[✗] {Style.RESET_ALL}Erreur: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)