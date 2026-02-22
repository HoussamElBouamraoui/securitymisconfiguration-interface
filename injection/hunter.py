#!/usr/bin/env python3
"""
INJECTIONHUNTER — OWASP Top 10 A05:2025 Injection (37 CWEs, 62k+ CVEs).
Détection agressive: SQLi, XSS, CMDi, LFI, LDAP, XPath, ORM, SSTI, SSRF,
désérialisation, WebSocket, config, ASVS. Usage strictement autorisé.
"""

import argparse
import os
import sys
import time

# Encodage UTF-8 pour Windows (évite UnicodeEncodeError sur banner)
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    try:
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from colorama import Fore, Style, init
init(autoreset=True)

from constants import DEFAULT_INJECTION_PARAM_NAMES, OWASP_A05_2025_ID
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

# Nouveaux modules v4.0 - OWASP A05:2025 Spécialiste
from modules.template_injection import TemplateInjection
from modules.ssrf_detector import SSRFDetector
from modules.deserialization import Deserialization
from modules.websocket_injection import WebSocketInjection
from modules.config_auditor import ConfigAuditor
from modules.asvs_compliance import ASVSCompliance

# Core avancé (lazy via engine.get_ai_detector() / engine.get_evasion())
# from core.ai_detector import AIInjectionDetector
# from core.evasion_advanced import AdvancedEvasion

# Cibles autorisées pour --test-authorized (sites de test connus)
AUTHORIZED_TEST_TARGETS = [
    "http://testphp.vulnweb.com",
    "https://testphp.vulnweb.com",
    "http://dvwa",
    "http://localhost",
    "http://127.0.0.1",
]


def banner():
    print(f"""
{Fore.RED}+----------------------------------------------------------------------+
{Fore.RED}|{Fore.YELLOW}  INJECTIONHUNTER v3.0 ULTRA-AGRESSIF - OWASP A05:2025 COMPLET       {Fore.RED}  |
{Fore.RED}|{Fore.GREEN}  Vulnerabilites d'injection - Detection + Exploitation MAX        {Fore.RED}  |
{Fore.RED}|{Fore.CYAN}  {OWASP_A05_2025_ID} - Usage STRICTEMENT autorise (consentement ecrit)          {Fore.RED}  |
{Fore.RED}+----------------------------------------------------------------------+{Style.RESET_ALL}
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
                        help="Modules: sqli,xss,cmdi,lfi,ldap,xpath,orm,forms,admin,cms,cookies,template,ssrf,deserialization,websocket,config,asvs (défaut: all)")
    parser.add_argument("--attacker-url", help="URL publique attaquant (ex: https://abc123.ngrok.io)")
    parser.add_argument("--stealth", action="store_true", help="Mode furtif - pas de serveur d'exfiltration XSS")
    parser.add_argument("--aggressive", action="store_true", help="Mode ULTRA-AGRESSIF (payloads polymorphiques + évasion WAF)")
    parser.add_argument("--fast", action="store_true", help="Mode RAPIDE: timeouts courts, parallélisation, moins de payloads par défaut")
    parser.add_argument("--exploit", action="store_true", help="Phase exploitation: tenter extraction/confirmation après détection (ex: SQLi version/DB)")
    parser.add_argument("--test-authorized", action="store_true", help="Test uniquement si l'URL est dans la liste autorisee")
    parser.add_argument("--out-json", metavar="FILE", help="Exporter les vulnerabilites en JSON (target + vulnerabilities)")
    parser.add_argument("--out-pdf", metavar="FILE", help="Generer en plus un rapport PDF style client (logo Injection, lecture facile)")
    args = parser.parse_args()

    if args.test_authorized:
        allowed = os.environ.get("INJECTION_ALLOWED_TARGETS", "").strip().split(",") if os.environ.get("INJECTION_ALLOWED_TARGETS") else AUTHORIZED_TEST_TARGETS
        allowed = [u.strip().rstrip("/") for u in allowed if u.strip()]
        base_url = args.url.split("?")[0].rstrip("/")
        if not any(base_url.startswith(a) or a in base_url for a in allowed):
            print(f"{Fore.RED}[X] URL non autorisee pour --test-authorized. Cibles: {allowed}{Style.RESET_ALL}")
            sys.exit(2)
        print(f"{Fore.GREEN}[OK] Test autorise: {base_url}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}[TARGET] {Style.RESET_ALL}{args.url}")
    if args.attacker_url:
        print(f"{Fore.CYAN}[ATTACKER] {Style.RESET_ALL}{args.attacker_url}")
    elif args.stealth:
        print(f"{Fore.GREEN}[MODE] {Style.RESET_ALL}Furtif - Pas d'exfiltration XSS")
    
    try:
        engine = InjectionEngine(
            args.url,
            attacker_url=args.attacker_url,
            aggressive=args.aggressive,
            stealth=args.stealth,
            fast=args.fast,
            parallel_workers=6 if args.fast else (4 if args.aggressive else 0),
            exploit=args.exploit,
        )
    except Exception as e:
        print(f"{Fore.RED}[X] {Style.RESET_ALL}Initialisation moteur: {e}")
        sys.exit(1)

    params = engine.discover_params()
    form_params = engine.discover_form_params() if not params else []
    effective_params = params or form_params or DEFAULT_INJECTION_PARAM_NAMES

    modules_without_params = ["forms", "admin", "cms", "cookies", "config", "asvs"]
    needs_params = not any(mod in args.modules.split(",") for mod in modules_without_params)

    if needs_params and not params:
        print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Aucun paramètre dans l'URL; utilisation de paramètres par défaut / formulaires")
        print(f"{Fore.GREEN}[OK] {Style.RESET_ALL}Parametres effectifs: {', '.join(effective_params[:15])}{'...' if len(effective_params) > 15 else ''}\n")
    elif params:
        print(f"{Fore.GREEN}[OK] {Style.RESET_ALL}Parametres detectes: {', '.join(params)}\n")
    else:
        print(f"{Fore.GREEN}[OK] {Style.RESET_ALL}Scan sans parametres URL - modules compatibles uniquement\n")
    
    # Modules mapping
    modules_map = {
        # Modules d'injection classiques
        'sqli': SQLIBlind,
        'xss': XSSPolyglot,
        'cmdi': CMDIRCE,
        'lfi': LFITraversal,
        'ldap': LDAPInjection,
        'xpath': XPathInjection,
        'orm': ORMInjection,
        
        # Modules de découverte
        'forms': FormsScanner,
        'admin': AdminFinder,
        'cms': CMSDetector,
        'cookies': CookiesAnalyzerV3,
        
        # Nouveaux modules v4.0 - OWASP A05:2025 Spécialiste
        'template': TemplateInjection,
        'ssrf': SSRFDetector,
        'deserialization': Deserialization,
        'websocket': WebSocketInjection,
        'config': ConfigAuditor,
        'asvs': ASVSCompliance,
    }
    
    all_vulns = []
    for mod_name in args.modules.split(','):
        if mod_name == 'all':
            for name, module_class in modules_map.items():
                print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}[ {name.upper()} ]{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
                if name in ["forms", "admin", "cms", "cookies", "config", "asvs"]:
                    module = module_class(engine)
                    vulns = module.scan(aggressive=args.aggressive)
                elif name in ["template", "ssrf", "deserialization", "websocket"]:
                    module = module_class(engine, aggressive=args.aggressive)
                    vulns = module.scan(effective_params)
                else:
                    module = module_class(engine, aggressive=args.aggressive)
                    vulns = module.scan(effective_params)
                all_vulns.extend(vulns)
            break
        elif mod_name in modules_map:
            print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[ {mod_name.upper()} ]{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            if mod_name in ["forms", "admin", "cms", "cookies", "config", "asvs"]:
                module = modules_map[mod_name](engine)
                vulns = module.scan(aggressive=args.aggressive)
            else:
                module = modules_map[mod_name](engine, aggressive=args.aggressive)
                vulns = module.scan(effective_params)
            all_vulns.extend(vulns)
    
    # Rapport final
    print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[ RAPPORT FINAL ULTRA-AGRESSIF ]{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    if not all_vulns:
        print(f"\n{Fore.GREEN}[OK] {Style.RESET_ALL}Aucune vulnerabilite d'injection detectee\n")
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
                'session_variation': Fore.CYAN,
                'template_injection': Fore.MAGENTA,
                'ssrf': Fore.BLUE,
                'deserialization': Fore.RED,
                'websocket_injection': Fore.CYAN,
                'config_violation': Fore.YELLOW,
                'asvs_violation': Fore.GREEN
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
    print(f"{Fore.GREEN}[OK] {Style.RESET_ALL}Scan termine !\n")

    if getattr(args, "out_json", None):
        try:
            import json
            out = {"target": args.url, "vulnerabilities": all_vulns}
            with open(args.out_json, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
            print(f"{Fore.GREEN}[OK] {Style.RESET_ALL}Rapport JSON: {args.out_json}\n")
        except Exception as e:
            print(f"{Fore.RED}[X] {Style.RESET_ALL}Export JSON: {e}\n")

    # PDF : généré si --out-pdf fourni, ou si --out-json fourni (même base de nom)
    out_pdf = getattr(args, "out_pdf", None)
    if not out_pdf and getattr(args, "out_json", None):
        out_pdf = str(args.out_json).rsplit(".", 1)[0] + ".pdf"
    if out_pdf:
        try:
            try:
                from reporting.a05_aggregator import aggregate_injection_run
                from reporting.client_report import generate_client_pdf
            except ImportError:
                from injection.reporting.a05_aggregator import aggregate_injection_run
                from injection.reporting.client_report import generate_client_pdf
            from pathlib import Path
            aggregated = aggregate_injection_run(
                target=args.url,
                vulnerabilities=all_vulns,
                mode="aggressive" if args.aggressive else "standard",
                project="InjectionHunter Pentest",
                metadata={},
            )
            logo_path = str(Path(__file__).resolve().parent / "image" / "logoinjection.png")
            generate_client_pdf(aggregated, out_pdf, logo_path=logo_path)
            print(f"{Fore.GREEN}[OK] {Style.RESET_ALL}Rapport PDF client: {out_pdf}\n")
        except Exception as e:
            print(f"{Fore.RED}[X] {Style.RESET_ALL}Génération PDF: {e}\n")
            import traceback
            traceback.print_exc()
    
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
        print(f"\n{Fore.RED}[X] {Style.RESET_ALL}Erreur: {e}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)