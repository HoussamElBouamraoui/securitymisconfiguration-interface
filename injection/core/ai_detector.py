#!/usr/bin/env python3
"""
🤖 AI INJECTION DETECTOR ULTRA-AGRESSIF — OWASP A05:2025
Machine Learning pour false positive reduction et payload optimization
"""

import re
import time
import hashlib
from collections import defaultdict
from colorama import Fore, Style

class AIInjectionDetector:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self.vulns = []
        self.ml_models = self._initialize_ml_models()
        self.context_cache = {}
        self.payload_history = defaultdict(list)
        
    def _initialize_ml_models(self):
        """Initialiser les modèles ML simples"""
        return {
            'false_positive_filter': self._create_fp_filter(),
            'context_analyzer': self._create_context_analyzer(),
            'payload_optimizer': self._create_payload_optimizer(),
            'risk_scorer': self._create_risk_scorer()
        }
    
    def _create_fp_filter(self):
        """Créer un filtre de faux positifs"""
        # Patterns de faux positifs communs
        fp_patterns = {
            'html_comments': [r'<!--.*?-->', r'<!--.*$', r'^\s*<!--'],
            'javascript_strings': [r'["\'][^"\']*["\']', r'["\'][^"\']*alert[^"\']*["\']'],
            'css_content': [r'\{[^}]*\}', r'\.[a-zA-Z]+\s*\{'],
            'json_data': [r'\{[^}]*\}', r'\[[^\]]*\]'],
            'base64_content': [r'[A-Za-z0-9+/]{20,}={0,2}'],
            'url_encoded': [r'%[0-9A-Fa-f]{2}'],
            'html_entities': [r'&[a-zA-Z]+;', r'&#\d+;'],
            'debug_output': [r'debug', r'var_dump', r'print_r', r'console\.log'],
            'framework_output': [r'laravel', r'symfony', r'django', r'wordpress']
        }
        return fp_patterns
    
    def _create_context_analyzer(self):
        """Créer un analyseur de contexte"""
        return {
            'technology_detection': {
                'php': ['php', '.php', '$_', 'echo', 'print', 'var_dump'],
                'java': ['java', '.jsp', '.do', 'System.out', 'servlet'],
                'python': ['python', '.py', 'django', 'flask', 'print('],
                'nodejs': ['node', '.js', 'express', 'console.log'],
                'asp': ['asp', '.aspx', 'Response.Write', 'Server.'],
                'ruby': ['ruby', '.rb', 'rails', 'puts']
            },
            'framework_detection': {
                'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
                'laravel': ['laravel', 'artisan', 'blade'],
                'symfony': ['symfony', 'bundle', 'twig'],
                'django': ['django', 'admin', 'csrf'],
                'drupal': ['drupal', 'modules', 'themes'],
                'joomla': ['joomla', 'components', 'modules']
            },
            'database_detection': {
                'mysql': ['mysql', 'mysqli', 'pdo', 'innodb'],
                'postgresql': ['postgresql', 'pgsql', 'psql'],
                'mongodb': ['mongodb', 'mongo', 'bson'],
                'sqlite': ['sqlite', 'sqlite3'],
                'oracle': ['oracle', 'ora-', 'oci']
            }
        }
    
    def _create_payload_optimizer(self):
        """Créer un optimiseur de payloads"""
        return {
            'encoding_variations': {
                'url_encode': lambda x: x.replace(' ', '%20'),
                'double_encode': lambda x: x.replace('%', '%25'),
                'unicode_encode': lambda x: x.replace('<', '\\u003c'),
                'hex_encode': lambda x: x.replace('<', '\\x3c')
            },
            'case_variations': {
                'upper': lambda x: x.upper(),
                'lower': lambda x: x.lower(),
                'mixed': lambda x: ''.join(c.upper() if i % 2 else c.lower() for i, c in enumerate(x))
            },
            'comment_injection': {
                'sql': lambda x: x + '/* */',
                'html': lambda x: x + '<!-- -->',
                'js': lambda x: x + '/* */'
            }
        }
    
    def _create_risk_scorer(self):
        """Créer un évaluateur de risque"""
        return {
            'severity_weights': {
                'rce': 10.0,
                'sql_injection': 9.0,
                'xss': 8.0,
                'ssrf': 8.5,
                'lfi': 7.5,
                'deserialization': 9.5,
                'template_injection': 8.5,
                'command_injection': 9.0
            },
            'context_multipliers': {
                'production': 1.5,
                'financial': 2.0,
                'healthcare': 2.5,
                'government': 2.0,
                'internal': 1.2
            },
            'impact_factors': {
                'data_exposure': 1.5,
                'authentication_bypass': 2.0,
                'privilege_escalation': 1.8,
                'data_modification': 1.6
            }
        }
    
    def analyze_response(self, baseline, injected_resp, payload, vuln_type, param):
        """Analyser la réponse avec IA"""
        
        # 1. Filtrer les faux positifs
        if self._is_false_positive(injected_resp, payload, vuln_type):
            return None
        
        # 2. Analyser le contexte
        context = self._analyze_context(injected_resp)
        
        # 3. Optimiser le payload
        optimized_payload = self._optimize_payload(payload, context)
        
        # 4. Calculer le score de risque
        risk_score = self._calculate_risk_score(vuln_type, context)
        
        # 5. Générer l'évidence
        evidence = self._generate_evidence(injected_resp, payload, vuln_type, context)
        
        return {
            'type': vuln_type,
            'param': param,
            'payload': optimized_payload,
            'original_payload': payload,
            'context': context,
            'risk_score': risk_score,
            'evidence': evidence,
            'confidence': self._calculate_confidence(injected_resp, payload, vuln_type),
            'ai_detected': True
        }
    
    def _is_false_positive(self, resp, payload, vuln_type):
        """Détecter les faux positifs avec ML"""
        content = resp.text.lower()
        
        # Vérifier les patterns de faux positifs
        for category, patterns in self.ml_models['false_positive_filter'].items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    # Vérifier si le payload correspond au pattern
                    if self._payload_matches_pattern(payload, pattern):
                        return True
        
        # Vérifier les réponses génériques
        generic_responses = [
            'page not found', 'error 404', 'access denied',
            'invalid request', 'bad request', 'forbidden',
            'unauthorized', 'service unavailable'
        ]
        
        for generic in generic_responses:
            if generic in content and len(content) < 500:
                return True
        
        return False
    
    def _payload_matches_pattern(self, payload, pattern):
        """Vérifier si le payload correspond au pattern"""
        payload_lower = payload.lower()
        
        # Patterns spécifiques par type
        if 'html_comments' in pattern:
            return '<!--' in payload_lower or '-->' in payload_lower
        elif 'javascript_strings' in pattern:
            return 'alert(' in payload_lower or 'javascript:' in payload_lower
        elif 'base64_content' in pattern:
            return len(payload) > 20 and re.match(r'^[A-Za-z0-9+/]+={0,2}$', payload)
        
        return False
    
    def _analyze_context(self, resp):
        """Analyser le contexte de la réponse"""
        content = resp.text.lower()
        context = {
            'technology': self._detect_technology(content),
            'framework': self._detect_framework(content),
            'database': self._detect_database(content),
            'content_type': self._detect_content_type(resp),
            'response_size': len(resp.text),
            'status_code': resp.status_code,
            'headers': dict(resp.headers)
        }
        
        return context
    
    def _detect_technology(self, content):
        """Détecter la technologie utilisée"""
        detected = []
        for tech, indicators in self.ml_models['context_analyzer']['technology_detection'].items():
            for indicator in indicators:
                if indicator in content:
                    detected.append(tech)
                    break
        return detected
    
    def _detect_framework(self, content):
        """Détecter le framework utilisé"""
        detected = []
        for framework, indicators in self.ml_models['context_analyzer']['framework_detection'].items():
            for indicator in indicators:
                if indicator in content:
                    detected.append(framework)
                    break
        return detected
    
    def _detect_database(self, content):
        """Détecter la base de données utilisée"""
        detected = []
        for db, indicators in self.ml_models['context_analyzer']['database_detection'].items():
            for indicator in indicators:
                if indicator in content:
                    detected.append(db)
                    break
        return detected
    
    def _detect_content_type(self, resp):
        """Détecter le type de contenu"""
        content_type = resp.headers.get('content-type', '').lower()
        
        if 'html' in content_type:
            return 'html'
        elif 'json' in content_type:
            return 'json'
        elif 'xml' in content_type:
            return 'xml'
        elif 'text' in content_type:
            return 'text'
        else:
            return 'unknown'
    
    def _optimize_payload(self, payload, context):
        """Optimiser le payload selon le contexte"""
        if not self.aggressive:
            return payload
        
        optimized = payload
        
        # Optimisation selon la technologie
        if 'php' in context.get('technology', []):
            optimized = self._apply_php_optimization(optimized)
        elif 'java' in context.get('technology', []):
            optimized = self._apply_java_optimization(optimized)
        elif 'python' in context.get('technology', []):
            optimized = self._apply_python_optimization(optimized)
        
        # Optimisation selon le framework
        if 'wordpress' in context.get('framework', []):
            optimized = self._apply_wordpress_optimization(optimized)
        elif 'laravel' in context.get('framework', []):
            optimized = self._apply_laravel_optimization(optimized)
        
        return optimized
    
    def _apply_php_optimization(self, payload):
        """Appliquer l'optimisation PHP"""
        # Ajouter des techniques PHP spécifiques
        if 'union' in payload.lower():
            payload += ' -- '
        elif 'select' in payload.lower():
            payload = payload.replace('SELECT', 'SeLeCt')
        
        return payload
    
    def _apply_java_optimization(self, payload):
        """Appliquer l'optimisation Java"""
        # Techniques Java spécifiques
        if 'runtime' in payload.lower():
            payload = payload.replace('Runtime', 'Runtime'.upper())
        
        return payload
    
    def _apply_python_optimization(self, payload):
        """Appliquer l'optimisation Python"""
        # Techniques Python spécifiques
        if '__import__' in payload:
            payload = payload.replace('__import__', '__import__'.upper())
        
        return payload
    
    def _apply_wordpress_optimization(self, payload):
        """Appliquer l'optimisation WordPress"""
        # Techniques WordPress spécifiques
        if 'union' in payload.lower():
            payload += '/* wordpress */'
        
        return payload
    
    def _apply_laravel_optimization(self, payload):
        """Appliquer l'optimisation Laravel"""
        # Techniques Laravel spécifiques
        if 'select' in payload.lower():
            payload = payload.replace('SELECT', 'SeLeCt')
        
        return payload
    
    def _calculate_risk_score(self, vuln_type, context):
        """Calculer le score de risque"""
        base_score = self.ml_models['risk_scorer']['severity_weights'].get(vuln_type, 5.0)
        
        # Multiplicateurs de contexte
        multiplier = 1.0
        
        # Contexte de production
        if any(indicator in context.get('framework', []) for indicator in ['wordpress', 'drupal', 'joomla']):
            multiplier *= 1.3
        
        # Base de données sensible
        if context.get('database'):
            multiplier *= 1.2
        
        # Taille de réponse importante
        if context.get('response_size', 0) > 10000:
            multiplier *= 1.1
        
        return min(10.0, base_score * multiplier)
    
    def _calculate_confidence(self, resp, payload, vuln_type):
        """Calculer la confiance de la détection"""
        confidence = 0.5  # Base confidence
        
        # Facteurs de confiance
        if resp.status_code != 200:
            confidence += 0.2
        
        if len(resp.text) > 1000:
            confidence += 0.1
        
        if vuln_type in ['sql_injection', 'xss', 'rce']:
            confidence += 0.2
        
        # Vérifier les indicateurs spécifiques
        content = resp.text.lower()
        if 'error' in content or 'exception' in content:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _generate_evidence(self, resp, payload, vuln_type, context):
        """Générer une évidence détaillée"""
        evidence_parts = []
        
        # Type de vulnérabilité
        evidence_parts.append(f"{vuln_type.upper()} detected")
        
        # Contexte technologique
        if context.get('technology'):
            evidence_parts.append(f"Technology: {', '.join(context['technology'])}")
        
        # Framework
        if context.get('framework'):
            evidence_parts.append(f"Framework: {', '.join(context['framework'])}")
        
        # Base de données
        if context.get('database'):
            evidence_parts.append(f"Database: {', '.join(context['database'])}")
        
        # Indicateurs spécifiques
        content = resp.text.lower()
        if 'error' in content:
            evidence_parts.append("Error response detected")
        if 'stack trace' in content:
            evidence_parts.append("Stack trace visible")
        
        return " | ".join(evidence_parts)
    
    def learn_from_response(self, resp, payload, was_vulnerable):
        """Apprendre de la réponse pour améliorer les détections futures"""
        # Créer un fingerprint de la réponse
        fingerprint = hashlib.md5(f"{resp.status_code}{len(resp.text)}{resp.text[:200]}".encode()).hexdigest()
        
        # Stocker l'historique
        self.payload_history[fingerprint].append({
            'payload': payload,
            'vulnerable': was_vulnerable,
            'timestamp': time.time(),
            'status_code': resp.status_code,
            'content_length': len(resp.text)
        })
        
        # Limiter l'historique
        if len(self.payload_history[fingerprint]) > 10:
            self.payload_history[fingerprint] = self.payload_history[fingerprint][-10:]
    
    def get_statistics(self):
        """Obtenir les statistiques de détection"""
        total_tests = sum(len(history) for history in self.payload_history.values())
        true_positives = sum(
            sum(1 for item in history if item['vulnerable'])
            for history in self.payload_history.values()
        )
        
        return {
            'total_tests': total_tests,
            'true_positives': true_positives,
            'false_positive_rate': (total_tests - true_positives) / max(total_tests, 1),
            'unique_fingerprints': len(self.payload_history)
        }
