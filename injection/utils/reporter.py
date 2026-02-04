#!/usr/bin/env python3
"""
📊 Rapport HTML Professionnel — Format PFE-ready
"""

import json
import time
from datetime import datetime

class HTMLReporter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.vulnerabilities = []
        self.start_time = time.time()
    
    def add_vulnerability(self, vuln):
        self.vulnerabilities.append(vuln)
    
    def generate_report(self, filename="report.html"):
        end_time = time.time()
        duration = end_time - self.start_time
        
        # Compter vulns par type
        vuln_counts = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
        
        # Générer HTML
        html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport de Sécurité - {self.target_url}</title>
    <style>
        :root {{
            --primary: #2c3e50;
            --danger: #e74c3c;
            --warning: #f39c12;
            --success: #27ae60;
            --info: #3498db;
            --light: #ecf0f1;
            --dark: #34495e;
        }}
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f8f9fa;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        header {{
            background: var(--primary);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
        }}
        .subtitle {{
            font-size: 1.2rem;
            opacity: 0.9;
        }}
        .summary {{
            display: flex;
            justify-content: space-around;
            padding: 20px;
            background: var(--light);
            border-bottom: 1px solid #ddd;
        }}
        .summary-item {{
            text-align: center;
            padding: 15px;
        }}
        .summary-number {{
            font-size: 2.5rem;
            font-weight: bold;
            margin: 10px 0;
        }}
        .summary-danger {{ color: var(--danger); }}
        .summary-warning {{ color: var(--warning); }}
        .summary-success {{ color: var(--success); }}
        .vuln-list {{
            padding: 30px;
        }}
        .vuln-item {{
            border-left: 4px solid var(--info);
            padding: 20px;
            margin-bottom: 20px;
            background: #f8f9fa;
            border-radius: 0 8px 8px 0;
            transition: transform 0.2s;
        }}
        .vuln-item:hover {{
            transform: translateX(5px);
        }}
        .vuln-item.sqli {{ border-left-color: var(--danger); }}
        .vuln-item.xss {{ border-left-color: var(--warning); }}
        .vuln-item.cmdi {{ border-left-color: var(--danger); }}
        .vuln-item.lfi {{ border-left-color: var(--danger); }}
        .vuln-item.admin {{ border-left-color: var(--info); }}
        .vuln-item.cms {{ border-left-color: var(--success); }}
        .vuln-item.form {{ border-left-color: var(--dark); }}
        .vuln-item.cookie {{ border-left-color: var(--dark); }}
        .vuln-title {{
            font-size: 1.4rem;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
        }}
        .vuln-type {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 15px;
            font-size: 0.9rem;
            font-weight: bold;
            margin-right: 10px;
        }}
        .type-sqli, .type-cmdi, .type-lfi {{ background: var(--danger); color: white; }}
        .type-xss {{ background: var(--warning); color: white; }}
        .type-admin, .type-cms {{ background: var(--success); color: white; }}
        .type-form, .type-cookie {{ background: var(--dark); color: white; }}
        .vuln-detail {{
            margin: 8px 0;
            padding-left: 20px;
        }}
        .vuln-payload {{
            background: #e9ecef;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            overflow-x: auto;
        }}
        .remediation {{
            background: #e8f4f8;
            padding: 20px;
            border-radius: 8px;
            margin-top: 30px;
        }}
        .remediation h2 {{
            color: var(--primary);
            margin-bottom: 15px;
        }}
        .remediation ul {{
            padding-left: 20px;
        }}
        .remediation li {{
            margin-bottom: 10px;
        }}
        footer {{
            text-align: center;
            padding: 20px;
            background: var(--dark);
            color: white;
            font-size: 0.9rem;
        }}
        @media (max-width: 768px) {{
            .summary {{
                flex-direction: column;
            }}
            .summary-item {{
                margin-bottom: 15px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Rapport de Sécurité</h1>
            <div class="subtitle">InjectionHunter v2.0 - OWASP A05:2025</div>
            <div class="subtitle">Cible: {self.target_url}</div>
            <div class="subtitle">Date: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</div>
        </header>
        
        <div class="summary">
            <div class="summary-item">
                <div class="summary-number summary-danger">{len([v for v in self.vulnerabilities if v['type'] in ['sqli', 'cmdi', 'lfi']])}</div>
                <div>Vulnérabilités critiques</div>
            </div>
            <div class="summary-item">
                <div class="summary-number summary-warning">{len([v for v in self.vulnerabilities if v['type'] == 'xss'])}</div>
                <div>Vulnérabilités élevées</div>
            </div>
            <div class="summary-item">
                <div class="summary-number summary-success">{len(self.vulnerabilities)}</div>
                <div>Total vulnérabilités</div>
            </div>
            <div class="summary-item">
                <div class="summary-number">{duration:.1f}s</div>
                <div>Durée du scan</div>
            </div>
        </div>
        
        <div class="vuln-list">
            <h2>📋 Détail des vulnérabilités</h2>
            {''.join(self._generate_vuln_html(vuln) for vuln in self.vulnerabilities) or '<div class="info">Aucune vulnérabilité détectée</div>'}
        </div>
        
        <div class="remediation">
            <h2>🛡️ Recommandations de correction</h2>
            <ul>
                <li><strong>SQL Injection:</strong> Utilisez des requêtes préparées (Prepared Statements) ou un ORM. Validez et échappez toutes les entrées utilisateur.</li>
                <li><strong>XSS:</strong> Échappez toutes les sorties avec des fonctions comme htmlspecialchars(). Implémentez une Content Security Policy (CSP).</li>
                <li><strong>Command Injection:</strong> Évitez d'utiliser les entrées utilisateur dans des commandes système. Utilisez des API sécurisées.</li>
                <li><strong>LFI:</strong> Ne pas utiliser les entrées utilisateur pour construire des chemins de fichiers. Utilisez des listes blanches.</li>
                <li><strong>Cookies:</strong> Activez les flags Secure et HttpOnly sur tous les cookies sensibles.</li>
                <li><strong>Formulaires:</strong> Implémentez des tokens CSRF pour toutes les actions sensibles.</li>
            </ul>
        </div>
        
        <footer>
            <p>Rapport généré par InjectionHunter v2.0 — Projet PFE Cybersécurité</p>
            <p>⚠️ Cet outil doit être utilisé UNIQUEMENT sur des systèmes avec autorisation écrite</p>
        </footer>
    </div>
</body>
</html>"""
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"\n{Fore.GREEN}[✓] {Style.RESET_ALL}Rapport HTML généré: {filename}")
        return filename
    
    def _generate_vuln_html(self, vuln):
        vuln_type = vuln['type']
        color_class = {
            'sqli': 'sqli',
            'xss': 'xss',
            'cmdi': 'cmdi',
            'lfi': 'lfi',
            'admin': 'admin',
            'cms': 'cms',
            'form': 'form',
            'cookie': 'cookie'
        }.get(vuln_type, 'info')
        
        return f"""
        <div class="vuln-item {color_class}">
            <div class="vuln-title">
                <span class="vuln-type type-{vuln_type}">{vuln_type.upper()}</span>
                {vuln.get('param', vuln.get('path', vuln.get('name', 'Inconnu')))}
            </div>
            <div class="vuln-detail"><strong>Preuve:</strong> {vuln.get('evidence', 'N/A')}</div>
            {f'<div class="vuln-detail"><strong>Payload:</strong></div><div class="vuln-payload">{vuln["payload"]}</div>' if 'payload' in vuln else ''}
            {f'<div class="vuln-detail"><strong>URL:</strong> <a href="{vuln["url"]}" target="_blank">{vuln["url"]}</a></div>' if 'url' in vuln else ''}
        </div>
        """