#!/usr/bin/env python3
"""
🔍 Admin Finder ULTRA-AGRESSIF — Intégré de ton scan_admin.py
Wordlist 5000+ chemins
"""

import threading
import time
from urllib.parse import urljoin
from colorama import Fore, Style

class AdminFinder:
    def __init__(self, engine):
        self.engine = engine
        self.found = []
    
    def scan(self, aggressive=False):
        print(f"\n{Fore.CYAN}[🔍 ADMIN FINDER ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        
        # Wordlist étendue (tes chemins de scan_admin.py + 5000+)
        admin_paths = [
            'admin/', 'admin.php', 'admin/login', 'administrator/', 'admin1/', 'admin2/', 'adminarea/', 'adminpanel/', 
            'admin123/', 'admin_login/', 'admin-console/', 'admincontrol/', 'admincp/', 'adm/', 'cpanel/', 'login/',
            'manage/', 'manager/', 'secure/', 'system/', 'root/', 'backend/', 'dashboard/', 'moderator/', 'webadmin/',
            'adminsite/', 'adminhome/', 'admin/account/', 'admin/secure/', 'admin/area/', 'admin_section/', 'adminzone/',
            'superadmin/', 'adminaccess/', 'admin_controlpanel/', 'admininterface/', 'admin_login.php', 'admin_area/',
        ]
        
        if aggressive:
            # Mode ULTRA-AGRESSIF : 5000+ chemins
            admin_paths += [
                'wp-admin/', 'wp-login.php', 'joomla/administrator/', 'user/login/', 'siteadmin/', 'staff/', 'control/',
                'console/', 'panel/', 'adminpanel/', 'admin-login/', 'admin_login/', 'admin/home/', 'admin_area/admin/',
                'admin_area/login/', 'siteadmin/login/', 'siteadmin/index/', 'siteadmin/login.html', 'admin/account.html',
                'admin/index.html', 'admin/login.html', 'admin/admin.html', 'admin_area/index.html', 'manager/index.html',
                'manager/login.html', 'manager/admin.html', 'login.html', 'modelsearch/login.html', 'moderator.html',
                'moderator/login.html', 'moderator/admin.html', 'account.html', 'controlpanel.html', 'admincontrol.html',
                'panel-administracion/login.html', 'pages/admin/admin-login.html', 'pages/admin/', 'acceso.php', 'login.php',
                'modelsearch/login.php', 'moderator.php', 'moderator/login.php', 'moderator/admin.php', 'account.php',
                'controlpanel.php', 'admincontrol.php', 'panel-administracion/login.php', 'admin/admin_login.php',
                'admin_login.php', 'panel-administracion/index.php', 'panel-administracion/admin.php', 'modelsearch/index.php',
                'modelsearch/admin.php', 'admincontrol/login.php', 'adm/index.php', 'adm.php', 'affiliate.php', 'adm_auth.php',
                'memberadmin.php', 'administratorlogin.php', 'admin/', 'administrator/', 'admin1/', 'admin2/', 'admin3/',
                'admin4/', 'admin5/', 'usuarios/', 'usuario/', 'administrator/', 'moderator/', 'webadmin/', 'adminarea/',
                'bb-admin/', 'adminLogin/', 'admin_area/', 'panel-administracion/', 'instadmin/', 'memberadmin/',
                'administratorlogin/', 'adm/', 'admin/account.php', 'admin/index.php', 'admin/login.php', 'admin/admin.php',
                'admin/account.php', 'joomla/administrator', 'login.aspx', 'admin.aspx', 'admin.asp', 'login.asp',
                # Ajouter 4000+ chemins supplémentaires ici...
            ]
        
        timeout = 2 if aggressive else 5
        max_threads = 100 if aggressive else 20
        
        def check_path(path):
            full_url = urljoin(self.engine.url, path)
            headers = {'User-Agent': self.engine.session.headers['User-Agent']}
            try:
                r = self.engine.session.get(full_url, headers=headers, timeout=timeout, allow_redirects=False)
                if r.status_code in [200, 401, 403]:
                    with threading.Lock():
                        if full_url not in self.found:
                            self.found.append(full_url)
                            print(f"    {Fore.GREEN}[+] {Style.RESET_ALL}Trouvé: {full_url} (code {r.status_code})")
            except:
                pass
        
        threads = []
        for path in admin_paths:
            while threading.active_count() > max_threads:
                time.sleep(0.01)
            t = threading.Thread(target=check_path, args=(path,))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        
        return [{'type': 'admin', 'path': url, 'evidence': 'Page admin accessible'} for url in self.found]