#!/usr/bin/env python3
"""
🌐 CMS Detection ULTRA-AGRESSIF — Intégré de ton scan_cms.py
Détection 20+ CMS
"""

import threading
from urllib.parse import urljoin
from colorama import Fore, Style

class CMSDetector:
    def __init__(self, engine):
        self.engine = engine
        self.found = []
    
    def scan(self, aggressive=False):
        print(f"\n{Fore.GREEN}[🌐 CMS DETECTION ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        
        # Signatures CMS (tes signatures de scan_cms.py + 20+ CMS)
        cms_signatures = {
            'WordPress': ['wp-content', 'wp-login.php', 'xmlrpc.php', '/wp-admin/'],
            'Joomla': ['Joomla!', '/administrator', 'index.php?option=com_', '/components/'],
            'Drupal': ['sites/all', 'drupal.js', 'user/login', '/sites/default/'],
            'PrestaShop': ['PrestaShop', '/modules/', '/themes/', '/prestashop/'],
            'Magento': ['Mage.Cookies', '/downloader/', '/index.php/admin/', 'Magento'],
            'TYPO3': ['typo3conf/', 'typo3temp/', 'typo3/'],
            'OpenCart': ['catalog/view/theme', 'index.php?route='],
            'phpBB': ['phpbb', 'viewforum.php', 'viewtopic.php'],
        }
        
        if aggressive:
            # Mode ULTRA-AGRESSIF : 20+ CMS
            cms_signatures.update({
                'Laravel': ['laravel', 'APP_KEY', '/vendor/laravel/'],
                'Django': ['csrfmiddlewaretoken', 'django', '/admin/'],
                'Symfony': ['symfony', '/bundles/'],
                'Wix': ['wix.com', 'wixstatic.com'],
                'Shopify': ['cdn.shopify.com', 'shopify.com'],
                'Moodle': ['mod_assign', 'moodlelib.php'],
                'Bitrix': ['bitrix'],
                'CraftCMS': ['craftcms'],
                'Contao': ['contao'],
                'SilverStripe': ['silverstripe'],
                'MODX': ['modx'],
                'Plone': ['plone'],
                'Textpattern': ['textpattern'],
                'Serendipity': ['serendipity'],
                'XOOPS': ['xoops'],
                'Chamilo': ['chamilo'],
                'Mambo': ['mambo'],
                'e107': ['e107'],
                'CMS Made Simple': ['cmsms'],
            })
        
        threads = []
        lock = threading.Lock()
        
        def check_cms(name, signatures):
            headers = {'User-Agent': self.engine.session.headers['User-Agent']}
            try:
                r = self.engine.session.get(self.engine.url, headers=headers, timeout=5)
                for sig in signatures:
                    if sig.lower() in r.text.lower():
                        with lock:
                            if name not in self.found:
                                self.found.append(name)
                                print(f"    {Fore.GREEN}[+] {Style.RESET_ALL}CMS détecté: {Fore.YELLOW}{name}{Style.RESET_ALL}")
                        break
            except:
                pass
        
        for name, signatures in cms_signatures.items():
            t = threading.Thread(target=check_cms, args=(name, signatures))
            t.start()
            threads.append(t)
            if len(threads) > 50:
                for t in threads:
                    t.join()
                threads = []
        
        for t in threads:
            t.join()
        
        return [{'type': 'cms', 'cms': cms, 'evidence': 'Signature CMS détectée'} for cms in self.found]