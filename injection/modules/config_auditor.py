#!/usr/bin/env python3
"""
🔧 CONFIG AUDITOR ULTRA-AGRESSIF — OWASP A05:2025
Security Misconfiguration Detection - Apache, Nginx, PHP, Database configs
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

class ConfigAuditor:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self.vulns = []
    
    def scan(self, params=None, aggressive=False):
        print(f"\n{Fore.CYAN}[🔧 CONFIG AUDITOR ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        
        # Tests de configuration de sécurité
        config_tests = {
            'security_headers': self._test_security_headers,
            'default_credentials': self._test_default_credentials,
            'backup_files': self._test_backup_files,
            'debug_endpoints': self._test_debug_endpoints,
            'information_disclosure': self._test_information_disclosure,
            'directory_listing': self._test_directory_listing,
            'error_pages': self._test_error_pages,
            'config_files': self._test_config_files
        }
        
        for test_name, test_func in config_tests.items():
            print(f"  → Test {test_name.replace('_', ' ').title()}")
            try:
                test_func()
            except Exception as e:
                print(f"    {Fore.YELLOW}[!] {Style.RESET_ALL}Erreur {test_name}: {e}")
        
        return self.vulns
    
    def _test_security_headers(self):
        """Tester les en-têtes de sécurité"""
        try:
            resp = self.engine.session.get(self.engine.url, timeout=10)
            headers = resp.headers
            
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS filtering',
                'X-Content-Type-Options': 'MIME type sniffing',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content Security Policy',
                'Referrer-Policy': 'Referrer policy',
                'Feature-Policy': 'Feature policy',
                'Permissions-Policy': 'Permissions policy'
            }
            
            missing_headers = []
            weak_headers = []
            
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
                elif header == 'X-Frame-Options' and headers[header] not in ['DENY', 'SAMEORIGIN']:
                    weak_headers.append(f"{header}: {headers[header]}")
                elif header == 'X-XSS-Protection' and headers[header] != '1; mode=block':
                    weak_headers.append(f"{header}: {headers[header]}")
                elif header == 'Strict-Transport-Security' and 'max-age=' not in headers[header]:
                    weak_headers.append(f"{header}: {headers[header]}")
            
            if missing_headers:
                self.vulns.append({
                    'type': 'missing_security_headers',
                    'missing_headers': missing_headers,
                    'evidence': f'Missing {len(missing_headers)} security headers',
                    'url': self.engine.url
                })
                print(f"    {Fore.RED}[!] {Style.RESET_ALL}{len(missing_headers)} en-têtes manquants")
            
            if weak_headers:
                self.vulns.append({
                    'type': 'weak_security_headers',
                    'weak_headers': weak_headers,
                    'evidence': f'Weak {len(weak_headers)} security headers',
                    'url': self.engine.url
                })
                print(f"    {Fore.YELLOW}[!] {Style.RESET_ALL}{len(weak_headers)} en-têtes faibles")
                
        except Exception as e:
            pass
    
    def _test_default_credentials(self):
        """Tester les identifiants par défaut"""
        default_creds = [
            # Admin panels
            ('/admin', 'admin', 'admin'),
            ('/admin', 'admin', 'password'),
            ('/admin', 'root', 'root'),
            ('/admin', 'admin', '123456'),
            ('/administrator', 'admin', 'admin'),
            ('/login', 'admin', 'admin'),
            ('/wp-admin', 'admin', 'password'),
            ('/phpmyadmin', 'root', ''),
            ('/phpmyadmin', 'root', 'root'),
            
            # Router/Network devices
            ('/', 'admin', 'admin'),
            ('/', 'admin', 'password'),
            ('/', 'root', 'admin'),
            
            # Database
            ('/phpmyadmin', 'root', ''),
            ('/mysql', 'root', ''),
            ('/pgadmin', 'postgres', 'postgres'),
        ]
        
        for path, username, password in default_creds:
            try:
                test_url = urljoin(self.engine.url, path)
                
                # Essayer l'accès sans auth
                resp = self.engine.session.get(test_url, timeout=5)
                
                if resp.status_code == 200:
                    # Vérifier si c'est une page de login
                    if any(keyword in resp.text.lower() for keyword in ['login', 'password', 'auth']):
                        # Essayer les identifiants par défaut
                        login_data = {
                            'username': username,
                            'password': password,
                            'user': username,
                            'pass': password,
                            'log': username,
                            'pwd': password
                        }
                        
                        for field_name, field_value in login_data.items():
                            try:
                                login_resp = self.engine.session.post(test_url, 
                                                                   data={field_name: field_value}, 
                                                                   timeout=5)
                                
                                if login_resp.status_code == 302 or 'dashboard' in login_resp.text.lower():
                                    self.vulns.append({
                                        'type': 'default_credentials',
                                        'path': path,
                                        'username': username,
                                        'password': password,
                                        'evidence': f'Default credentials work on {path}',
                                        'url': test_url
                                    })
                                    print(f"    {Fore.RED}[!] {Style.RESET_ALL}Identifiants par défaut: {username}:{password} sur {path}")
                                    break
                                    
                            except:
                                continue
                                
            except:
                continue
    
    def _test_backup_files(self):
        """Tester les fichiers de sauvegarde exposés"""
        backup_files = [
            '.bak', '.backup', '.old', '.orig', '.save',
            '.zip', '.tar', '.tar.gz', '.tgz', '.rar',
            '.sql', '.dump', '.db', '.sqlite',
            '.conf', '.config', '.ini', '.cfg',
            'backup.zip', 'backup.tar.gz', 'db.sql',
            'wp-config.php.bak', 'config.php.bak',
            'database.sql', 'dump.sql'
        ]
        
        # Extraire le nom de base de l'URL
        parsed = urlparse(self.engine.url)
        base_name = parsed.path.split('/')[-1] if parsed.path != '/' else 'index'
        
        for backup_ext in backup_files:
            try:
                backup_url = f"{self.engine.url.rstrip('/')}/{base_name}{backup_ext}"
                resp = self.engine.session.get(backup_url, timeout=5)
                
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Vérifier si c'est vraiment un fichier de sauvegarde
                    if any(indicator in resp.text[:500] for indicator in [
                        'CREATE TABLE', 'INSERT INTO', 'database', 'password',
                        '<?php', 'define(', 'DB_PASSWORD', 'mysql_connect',
                        '-----BEGIN', 'PK\x03\x04', '\x1f\x8b\x08'
                    ]):
                        self.vulns.append({
                            'type': 'backup_file_exposed',
                            'file': backup_url,
                            'size': len(resp.text),
                            'evidence': f'Backup file exposed: {backup_ext}',
                            'url': backup_url
                        })
                        print(f"    {Fore.RED}[!] {Style.RESET_ALL}Fichier de sauvegarde exposé: {backup_ext}")
                        
            except:
                continue
    
    def _test_debug_endpoints(self):
        """Tester les endpoints de debug"""
        debug_endpoints = [
            '/debug', '/test', '/dev', '/development',
            '/phpinfo.php', '/info.php', '/test.php',
            '/server-info', '/server-status', '/status',
            '/.env', '/environment', '/config',
            '/logs', '/error_log', '/access_log',
            '/phpmyadmin', '/adminer', '/mysql',
            '/web.config', '/.htaccess', '/.git/config'
        ]
        
        for endpoint in debug_endpoints:
            try:
                test_url = urljoin(self.engine.url, endpoint)
                resp = self.engine.session.get(test_url, timeout=5)
                
                if resp.status_code == 200:
                    # Vérifier si c'est une page de debug
                    debug_indicators = [
                        'phpinfo()', 'PHP Version', 'Server API',
                        'Environment Variables', 'Apache Environment',
                        'Configuration File', 'Loaded Modules',
                        'DEBUG', 'TRACE', 'DEVELOPMENT',
                        'mysql_connect', 'database', 'password'
                    ]
                    
                    if any(indicator in resp.text for indicator in debug_indicators):
                        self.vulns.append({
                            'type': 'debug_endpoint',
                            'endpoint': endpoint,
                            'evidence': f'Debug endpoint exposed: {endpoint}',
                            'url': test_url
                        })
                        print(f"    {Fore.RED}[!] {Style.RESET_ALL}Endpoint de debug: {endpoint}")
                        
            except:
                continue
    
    def _test_information_disclosure(self):
        """Tester la divulgation d'informations"""
        try:
            # Forcer une erreur 404
            test_url = self.engine.url + '/nonexistent_file_' + str(int(time.time())) + '.php'
            resp = self.engine.session.get(test_url, timeout=5)
            
            # Analyser la page d'erreur
            error_indicators = [
                'Apache/2.', 'nginx/', 'PHP/', 'MySQL',
                'Server at', 'Port 80', 'DocumentRoot',
                'Stack trace:', 'Fatal error:', 'Warning:',
                'File not found', 'Internal Server Error',
                'Microsoft-IIS', 'X-Powered-By'
            ]
            
            disclosed_info = []
            for indicator in error_indicators:
                if indicator in resp.text:
                    disclosed_info.append(indicator)
            
            if disclosed_info:
                self.vulns.append({
                    'type': 'information_disclosure',
                    'disclosed_info': disclosed_info,
                    'evidence': f'Information disclosure in error page',
                    'url': test_url
                })
                print(f"    {Fore.YELLOW}[!] {Style.RESET_ALL}Divulgation d'informations: {len(disclosed_info)} éléments")
                
        except:
            pass
    
    def _test_directory_listing(self):
        """Tester le listing de répertoires"""
        test_dirs = [
            '/images/', '/uploads/', '/files/', '/backup/',
            '/logs/', '/temp/', '/cache/', '/admin/',
            '/includes/', '/lib/', '/src/', '/assets/'
        ]
        
        for test_dir in test_dirs:
            try:
                test_url = urljoin(self.engine.url, test_dir)
                resp = self.engine.session.get(test_url, timeout=5)
                
                # Indicateurs de directory listing
                listing_indicators = [
                    'Index of /', 'Directory Listing',
                    'Parent Directory', '[DIR]', '[TXT]',
                    '<pre>Index of', 'Directory Listing for'
                ]
                
                if any(indicator in resp.text for indicator in listing_indicators):
                    self.vulns.append({
                        'type': 'directory_listing',
                        'directory': test_dir,
                        'evidence': f'Directory listing enabled: {test_dir}',
                        'url': test_url
                    })
                    print(f"    {Fore.RED}[!] {Style.RESET_ALL}Directory listing: {test_dir}")
                    
            except:
                continue
    
    def _test_error_pages(self):
        """Tester les pages d'erreur personnalisées"""
        error_codes = [400, 401, 403, 404, 500, 502, 503]
        
        for code in error_codes:
            try:
                # Forcer l'erreur
                if code == 404:
                    test_url = self.engine.url + '/forced_404_error_' + str(int(time.time()))
                elif code == 500:
                    test_url = self.engine.url + '/?error=' + 'A' * 1000
                else:
                    test_url = self.engine.url + f'/forced_{code}_error'
                
                resp = self.engine.session.get(test_url, timeout=5)
                
                # Vérifier si la page d'erreur révèle des informations
                if resp.status_code == code:
                    error_info = resp.text[:500]
                    
                    sensitive_patterns = [
                        r'/.+?\.php', r'/.+?\.html', r'/.+?\.js',
                        r'/.+?/[^/]+', r'File not found in',
                        r'Call to undefined function',
                        r'Fatal error.*on line \d+',
                        r'Stack trace:#'
                    ]
                    
                    for pattern in sensitive_patterns:
                        if re.search(pattern, error_info):
                            self.vulns.append({
                                'type': 'error_page_disclosure',
                                'error_code': code,
                                'pattern': pattern,
                                'evidence': f'Error page {code} reveals sensitive info',
                                'url': test_url
                            })
                            print(f"    {Fore.YELLOW}[!] {Style.RESET_ALL}Page d'erreur {code} sensible")
                            break
                            
            except:
                continue
    
    def _test_config_files(self):
        """Tester les fichiers de configuration exposés"""
        config_files = [
            '/.env', '/.env.local', '/.env.production',
            '/config.php', '/config.ini', '/config.json',
            '/database.yml', '/database.php', '/db.php',
            '/wp-config.php', '/configuration.php',
            '/settings.py', '/settings.yml',
            '/application.properties', '/application.yml',
            '/web.config', '/appsettings.json'
        ]
        
        for config_file in config_files:
            try:
                test_url = urljoin(self.engine.url, config_file)
                resp = self.engine.session.get(test_url, timeout=5)
                
                if resp.status_code == 200 and len(resp.text) > 50:
                    # Vérifier si c'est vraiment un fichier de config
                    config_indicators = [
                        'DB_', 'DATABASE_', 'PASSWORD', 'SECRET',
                        'API_KEY', 'TOKEN', 'HOST', 'PORT',
                        'mysql_', 'postgres_', 'redis_',
                        'AWS_', 'GOOGLE_', 'AZURE_'
                    ]
                    
                    if any(indicator in resp.text for indicator in config_indicators):
                        self.vulns.append({
                            'type': 'config_file_exposed',
                            'file': config_file,
                            'size': len(resp.text),
                            'evidence': f'Configuration file exposed: {config_file}',
                            'url': test_url
                        })
                        print(f"    {Fore.RED}[!] {Style.RESET_ALL}Fichier de config exposé: {config_file}")
                        
            except:
                continue
