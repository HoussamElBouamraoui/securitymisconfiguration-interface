#!/usr/bin/env python3
"""
📋 Analyse Formulaires ULTRA-AGRESSIF — Intégré de ton scan_forms.py
"""

from bs4 import BeautifulSoup
from colorama import Fore, Style

class FormsScanner:
    def __init__(self, engine):
        self.engine = engine
    
    def scan(self, aggressive=False):
        print(f"\n{Fore.CYAN}[📋 ANALYSE FORMULAIRES ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        
        if aggressive:
            print(f"    {Fore.YELLOW}[⚡] {Style.RESET_ALL}Mode AGRESSIF activé - Analyse approfondie")
        
        try:
            resp = self.engine.session.get(self.engine.url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            forms = soup.find_all('form')
            
            if not forms:
                print(f"    {Fore.YELLOW}[!] {Style.RESET_ALL}Aucun formulaire trouvé")
                return []
            
            print(f"    {Fore.GREEN}[+] {Style.RESET_ALL}{len(forms)} formulaire(s) détecté(s)\n")
            
            results = []
            for i, form in enumerate(forms, 1):
                action = form.get('action', self.engine.url)
                method = form.get('method', 'GET').upper()
                enctype = form.get('enctype', 'application/x-www-form-urlencoded')
                
                print(f"    {Fore.CYAN}Formulaire #{i}{Style.RESET_ALL}")
                print(f"      Action: {action}")
                print(f"      Méthode: {method}")
                print(f"      Encodage: {enctype}")
                
                # Analyser les champs (comme dans ton scan_forms.py)
                inputs = form.find_all(['input', 'textarea', 'select'])
                sensitive_fields = []
                
                for inp in inputs:
                    field_type = inp.get('type', 'text' if inp.name == 'input' else inp.name)
                    field_name = inp.get('name', '[Sans nom]')
                    
                    # Détection champs sensibles (tes patterns de scan_forms.py)
                    if any(s in field_name.lower() for s in ['pass', 'pwd', 'secret', 'token', 'auth', 'key', 'credit', 'card']):
                        sensitive_fields.append(field_name)
                        print(f"      🔒 Champ sensible: {field_name} (type: {field_type})")
                    else:
                        print(f"      Champ: {field_name} (type: {field_type})")
                
                # Analyse sécurité (tes patterns de scan_forms.py)
                csrf_fields = form.find_all('input', {'name': lambda x: x and ('csrf' in x.lower() or 'token' in x.lower())})
                if csrf_fields:
                    print(f"      ✅ Protection CSRF détectée")
                else:
                    print(f"      ⚠️  Aucune protection CSRF détectée")
                
                if action.startswith('https://') or (not action.startswith('http') and self.engine.url.startswith('https://')):
                    print(f"      ✅ Formulaire sécurisé (HTTPS)")
                else:
                    print(f"      ⚠️  Formulaire non sécurisé (HTTP)")
                
                print()
                
                results.append({
                    'type': 'form',
                    'form_id': i,
                    'action': action,
                    'method': method,
                    'sensitive_fields': sensitive_fields,
                    'csrf_protected': bool(csrf_fields),
                    'https': action.startswith('https://') or (not action.startswith('http') and self.engine.url.startswith('https://')),
                })
            
            return results
        
        except Exception as e:
            print(f"    {Fore.RED}[✗] {Style.RESET_ALL}Erreur: {e}")
            return []