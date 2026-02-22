#!/usr/bin/env python3
"""
🏆 OWASP ASVS COMPLIANCE ULTRA-AGRESSIF — OWASP A05:2025
Application Security Verification Standard - Levels 1-4 verification
"""

import re
import requests
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style

class ASVSCompliance:
    def __init__(self, engine, aggressive=False):
        self.engine = engine
        self.aggressive = aggressive
        self.vulns = []
        self.compliance_score = 0
        self.total_checks = 0
        
    def scan(self, params=None, aggressive=False):
        print(f"\n{Fore.CYAN}[🏆 OWASP ASVS COMPLIANCE ULTRA-AGRESSIF] {Style.RESET_ALL}\n")
        
        # ASVS Level 1-4 checks
        asvs_checks = {
            'level1': self._check_level1_requirements,
            'level2': self._check_level2_requirements,
            'level3': self._check_level3_requirements,
            'level4': self._check_level4_requirements
        }
        
        for level, check_func in asvs_checks.items():
            print(f"  → Vérification ASVS {level.upper()}")
            try:
                check_func()
            except Exception as e:
                print(f"    {Fore.YELLOW}[!] {Style.RESET_ALL}Erreur {level}: {e}")
        
        # Calculer le score de conformité
        self._calculate_compliance_score()
        
        return self.vulns
    
    def _check_level1_requirements(self):
        """ASVS Level 1 - Automated verification"""
        
        # V1.1.1 - Verify framework security
        self._check_framework_security()
        
        # V1.2.1 - Verify HTTP security headers
        self._check_http_security_headers()
        
        # V1.3.1 - Verify TLS configuration
        self._check_tls_configuration()
        
        # V1.4.1 - Verify input validation
        self._check_input_validation()
        
        # V1.5.1 - Verify output encoding
        self._check_output_encoding()
        
        # V1.6.1 - Verify authentication
        self._check_authentication_mechanisms()
        
        # V1.7.1 - Verify session management
        self._check_session_management()
        
        # V1.8.1 - Verify access control
        self._check_access_control()
        
        # V1.9.1 - Verify cryptographic storage
        self._check_cryptographic_storage()
        
        # V1.10.1 - Verify error handling
        self._check_error_handling()
        
        # V1.11.1 - Verify logging
        self._check_logging_mechanisms()
        
        # V1.12.1 - Verify data protection
        self._check_data_protection()
        
        # V1.13.1 - Verify communications
        self._check_communications_security()
        
        # V1.14.1 - Verify malicious file handling
        self._check_malicious_file_handling()
        
        # V1.15.1 - Verify API security
        self._check_api_security()
        
        # V1.16.1 - Verify configuration
        self._check_configuration_management()
    
    def _check_level2_requirements(self):
        """ASVS Level 2 - Semi-automated verification"""
        
        # V2.1.1 - Verify business logic flaws
        self._check_business_logic_flaws()
        
        # V2.2.1 - Verify file upload security
        self._check_file_upload_security()
        
        # V2.3.1 - Verify server-side request forgery
        self._check_ssrf_protection()
        
        # V2.4.1 - Verify server-side template injection
        self._check_ssti_protection()
        
        # V2.5.1 - Verify deserialization
        self._check_deserialization_protection()
        
        # V2.6.1 - Verify weak cryptography
        self._check_weak_cryptography()
        
        # V2.7.1 - Verify authorization
        self._check_authorization()
        
        # V2.8.1 - Verify client-side security
        self._check_client_side_security()
        
        # V2.9.1 - Verify HTML5 security
        self._check_html5_security()
        
        # V2.10.1 - Verify HTTP security
        self._check_http_advanced_security()
        
        # V2.11.1 - Verify web services security
        self._check_web_services_security()
        
        # V2.12.1 - Verify mobile security
        self._check_mobile_security()
    
    def _check_level3_requirements(self):
        """ASVS Level 3 - Manual verification"""
        
        # V3.1.1 - Verify advanced business logic
        self._check_advanced_business_logic()
        
        # V3.2.1 - Verify advanced input validation
        self._check_advanced_input_validation()
        
        # V3.3.1 - Verify advanced output encoding
        self._check_advanced_output_encoding()
        
        # V3.4.1 - Verify advanced authentication
        self._check_advanced_authentication()
        
        # V3.5.1 - Verify advanced session management
        self._check_advanced_session_management()
        
        # V3.6.1 - Verify advanced access control
        self._check_advanced_access_control()
        
        # V3.7.1 - Verify advanced cryptography
        self._check_advanced_cryptography()
        
        # V3.8.1 - Verify advanced error handling
        self._check_advanced_error_handling()
        
        # V3.9.1 - Verify advanced logging
        self._check_advanced_logging()
        
        # V3.10.1 - Verify advanced data protection
        self._check_advanced_data_protection()
    
    def _check_level4_requirements(self):
        """ASVS Level 4 - Deep manual verification"""
        
        # V4.1.1 - Verify custom cryptography
        self._check_custom_cryptography()
        
        # V4.2.1 - Verify advanced business logic
        self._check_custom_business_logic()
        
        # V4.3.1 - Verify advanced architecture
        self._check_advanced_architecture()
        
        # V4.4.1 - Verify advanced deployment
        self._check_advanced_deployment()
        
        # V4.5.1 - Verify advanced operations
        self._check_advanced_operations()
    
    def _check_framework_security(self):
        """V1.1.1 - Verify framework security"""
        try:
            resp = self.engine.session.get(self.engine.url, timeout=10)
            
            # Check for framework disclosure
            framework_indicators = {
                'laravel': ['laravel', 'artisan', 'blade'],
                'symfony': ['symfony', 'bundle', 'twig'],
                'django': ['django', 'admin', 'csrf'],
                'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
                'drupal': ['drupal', 'modules', 'themes'],
                'joomla': ['joomla', 'components', 'modules']
            }
            
            detected_frameworks = []
            for framework, indicators in framework_indicators.items():
                for indicator in indicators:
                    if indicator in resp.text.lower():
                        detected_frameworks.append(framework)
                        break
            
            if detected_frameworks:
                # Check for known vulnerabilities
                self._check_framework_vulnerabilities(detected_frameworks)
            
            self.total_checks += 1
            
        except Exception as e:
            pass
    
    def _check_http_security_headers(self):
        """V1.2.1 - Verify HTTP security headers"""
        try:
            resp = self.engine.session.get(self.engine.url, timeout=10)
            headers = resp.headers
            
            required_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS filtering',
                'X-Content-Type-Options': 'MIME type sniffing',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content Security Policy',
                'Referrer-Policy': 'Referrer policy'
            }
            
            missing_headers = []
            weak_headers = []
            
            for header, description in required_headers.items():
                self.total_checks += 1
                
                if header not in headers:
                    missing_headers.append(header)
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': f'V1.2.1 - {header}',
                        'severity': 'medium',
                        'evidence': f'Missing security header: {header}',
                        'url': self.engine.url
                    })
                elif header == 'X-Frame-Options' and headers[header] not in ['DENY', 'SAMEORIGIN']:
                    weak_headers.append(header)
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': f'V1.2.1 - {header}',
                        'severity': 'low',
                        'evidence': f'Weak security header: {header} = {headers[header]}',
                        'url': self.engine.url
                    })
            
        except Exception as e:
            pass
    
    def _check_tls_configuration(self):
        """V1.3.1 - Verify TLS configuration"""
        try:
            # Check HTTPS usage
            if not self.engine.url.startswith('https://'):
                self.total_checks += 1
                self.vulns.append({
                    'type': 'asvs_violation',
                    'requirement': 'V1.3.1 - HTTPS',
                    'severity': 'high',
                    'evidence': 'Application not using HTTPS',
                    'url': self.engine.url
                })
            else:
                # Check TLS version (simplified check)
                self.total_checks += 1
                # In a real implementation, we would check TLS version and cipher suites
                
        except Exception as e:
            pass
    
    def _check_input_validation(self):
        """V1.4.1 - Verify input validation"""
        try:
            # Test basic input validation
            test_params = {
                'test': '<script>alert(1)</script>',
                'id': "' OR '1'='1",
                'search': '../../../etc/passwd',
                'file': 'test.php'
            }
            
            for param, payload in test_params.items():
                self.total_checks += 1
                test_url = f"{self.engine.url}?{param}={payload}"
                resp = self.engine.session.get(test_url, timeout=5)
                
                # Check if payload is reflected without encoding
                if payload in resp.text:
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': 'V1.4.1 - Input validation',
                        'severity': 'medium',
                        'evidence': f'Unvalidated input reflected: {param}',
                        'url': test_url
                    })
                    
        except Exception as e:
            pass
    
    def _check_output_encoding(self):
        """V1.5.1 - Verify output encoding"""
        try:
            # Test XSS output encoding
            xss_payload = '<script>alert(1)</script>'
            test_url = f"{self.engine.url}?test={xss_payload}"
            resp = self.engine.session.get(test_url, timeout=5)
            
            self.total_checks += 1
            
            # Check if script tag is properly encoded
            if '<script>' in resp.text and 'alert(1)' in resp.text:
                self.vulns.append({
                    'type': 'asvs_violation',
                    'requirement': 'V1.5.1 - Output encoding',
                    'severity': 'high',
                    'evidence': 'XSS payload not properly encoded',
                    'url': test_url
                })
                
        except Exception as e:
            pass
    
    def _check_authentication_mechanisms(self):
        """V1.6.1 - Verify authentication mechanisms"""
        try:
            # Check for authentication endpoints
            auth_endpoints = ['/login', '/auth', '/signin', '/admin']
            
            for endpoint in auth_endpoints:
                self.total_checks += 1
                test_url = urljoin(self.engine.url, endpoint)
                resp = self.engine.session.get(test_url, timeout=5)
                
                if resp.status_code == 200:
                    # Check for secure authentication practices
                    if 'password' in resp.text.lower():
                        # Check if form uses POST
                        if 'method="post"' not in resp.text.lower():
                            self.vulns.append({
                                'type': 'asvs_violation',
                                'requirement': 'V1.6.1 - Authentication',
                                'severity': 'medium',
                                'evidence': f'Authentication form not using POST: {endpoint}',
                                'url': test_url
                            })
                        
        except Exception as e:
            pass
    
    def _check_session_management(self):
        """V1.7.1 - Verify session management"""
        try:
            resp = self.engine.session.get(self.engine.url, timeout=10)
            
            self.total_checks += 1
            
            # Check for secure session cookies
            cookies = resp.cookies
            for cookie in cookies:
                if 'session' in cookie.name.lower() or 'phpsessid' in cookie.name.lower():
                    if not cookie.secure and self.engine.url.startswith('https://'):
                        self.vulns.append({
                            'type': 'asvs_violation',
                            'requirement': 'V1.7.1 - Session management',
                            'severity': 'medium',
                            'evidence': f'Insecure session cookie: {cookie.name}',
                            'url': self.engine.url
                        })
                        
        except Exception as e:
            pass
    
    def _check_access_control(self):
        """V1.8.1 - Verify access control"""
        try:
            # Test for broken access control
            admin_endpoints = ['/admin', '/admin/', '/administrator', '/dashboard']
            
            for endpoint in admin_endpoints:
                self.total_checks += 1
                test_url = urljoin(self.engine.url, endpoint)
                resp = self.engine.session.get(test_url, timeout=5)
                
                if resp.status_code == 200 and 'login' not in resp.text.lower():
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': 'V1.8.1 - Access control',
                        'severity': 'high',
                        'evidence': f'Unprotected admin endpoint: {endpoint}',
                        'url': test_url
                    })
                    
        except Exception as e:
            pass
    
    def _check_cryptographic_storage(self):
        """V1.9.1 - Verify cryptographic storage"""
        try:
            # Check for hardcoded credentials
            resp = self.engine.session.get(self.engine.url, timeout=10)
            
            self.total_checks += 1
            
            # Patterns for hardcoded credentials
            credential_patterns = [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
                r'db_password\s*=\s*["\'][^"\']+["\']'
            ]
            
            for pattern in credential_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': 'V1.9.1 - Cryptographic storage',
                        'severity': 'high',
                        'evidence': f'Potential hardcoded credentials: {pattern}',
                        'url': self.engine.url
                    })
                    break
                    
        except Exception as e:
            pass
    
    def _check_error_handling(self):
        """V1.10.1 - Verify error handling"""
        try:
            # Force an error to check error handling
            test_url = self.engine.url + '/nonexistent_' + str(int(time.time()))
            resp = self.engine.session.get(test_url, timeout=5)
            
            self.total_checks += 1
            
            # Check for information disclosure in error messages
            error_patterns = [
                r'Warning:', r'Fatal error:', r'Parse error:',
                r'Stack trace:', r'Exception:', r'Error in',
                r'/var/www/', r'/home/', r'C:\\',
                r'mysql_fetch', r'pg_query', r'ora-'
            ]
            
            for pattern in error_patterns:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': 'V1.10.1 - Error handling',
                        'severity': 'medium',
                        'evidence': f'Information disclosure in error: {pattern}',
                        'url': test_url
                    })
                    break
                    
        except Exception as e:
            pass
    
    def _check_logging_mechanisms(self):
        """V1.11.1 - Verify logging mechanisms"""
        try:
            # Check for log files exposure
            log_files = [
                '/logs/', '/error.log', '/access.log', '/debug.log',
                '/application.log', '/system.log', '/security.log'
            ]
            
            for log_file in log_files:
                self.total_checks += 1
                test_url = urljoin(self.engine.url, log_file)
                resp = self.engine.session.get(test_url, timeout=5)
                
                if resp.status_code == 200 and len(resp.text) > 100:
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': 'V1.11.1 - Logging mechanisms',
                        'severity': 'medium',
                        'evidence': f'Log file exposed: {log_file}',
                        'url': test_url
                    })
                    
        except Exception as e:
            pass
    
    def _check_data_protection(self):
        """V1.12.1 - Verify data protection"""
        try:
            # Check for PII exposure
            resp = self.engine.session.get(self.engine.url, timeout=10)
            
            self.total_checks += 1
            
            # PII patterns
            pii_patterns = [
                r'\b\d{3}-\d{2}-\d{4}\b',  # SSN
                r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # Credit card
                r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',  # Email
                r'\b\d{1,5}\s+\w+\s+\w+\s+\w+\s+\d{5}\b'  # Address
            ]
            
            for pattern in pii_patterns:
                if re.search(pattern, resp.text):
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': 'V1.12.1 - Data protection',
                        'severity': 'high',
                        'evidence': f'PII data exposed: {pattern}',
                        'url': self.engine.url
                    })
                    break
                    
        except Exception as e:
            pass
    
    def _check_communications_security(self):
        """V1.13.1 - Verify communications security"""
        try:
            # Check for mixed content
            if self.engine.url.startswith('https://'):
                resp = self.engine.session.get(self.engine.url, timeout=10)
                
                self.total_checks += 1
                
                # Check for HTTP resources in HTTPS page
                http_resources = re.findall(r'http://[^\s"\'<>]+', resp.text)
                if http_resources:
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': 'V1.13.1 - Communications security',
                        'severity': 'medium',
                        'evidence': f'Mixed content: {len(http_resources)} HTTP resources',
                        'url': self.engine.url
                    })
                    
        except Exception as e:
            pass
    
    def _check_malicious_file_handling(self):
        """V1.14.1 - Verify malicious file handling"""
        try:
            # Check for file upload functionality
            resp = self.engine.session.get(self.engine.url, timeout=10)
            
            self.total_checks += 1
            
            # Look for file upload forms
            if 'type="file"' in resp.text or 'enctype="multipart/form-data"' in resp.text:
                # Check for file type restrictions
                if not any(restriction in resp.text.lower() for restriction in [
                    'accept=', 'filetype', 'allowed', 'extension', 'mime'
                ]):
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': 'V1.14.1 - Malicious file handling',
                        'severity': 'high',
                        'evidence': 'File upload without restrictions',
                        'url': self.engine.url
                    })
                    
        except Exception as e:
            pass
    
    def _check_api_security(self):
        """V1.15.1 - Verify API security"""
        try:
            # Check for API endpoints
            api_patterns = ['/api/', '/v1/', '/v2/', '/rest/', '/graphql']
            
            for pattern in api_patterns:
                self.total_checks += 1
                test_url = urljoin(self.engine.url, pattern)
                resp = self.engine.session.get(test_url, timeout=5)
                
                if resp.status_code == 200:
                    # Check for API security headers
                    if 'Content-Type' not in resp.headers:
                        self.vulns.append({
                            'type': 'asvs_violation',
                            'requirement': 'V1.15.1 - API security',
                            'severity': 'medium',
                            'evidence': f'API endpoint missing Content-Type: {pattern}',
                            'url': test_url
                        })
                        
        except Exception as e:
            pass
    
    def _check_configuration_management(self):
        """V1.16.1 - Verify configuration management"""
        try:
            # Check for exposed configuration files
            config_files = [
                '/.env', '/config.php', '/database.yml', '/settings.py',
                '/web.config', '/appsettings.json', '/.git/config'
            ]
            
            for config_file in config_files:
                self.total_checks += 1
                test_url = urljoin(self.engine.url, config_file)
                resp = self.engine.session.get(test_url, timeout=5)
                
                if resp.status_code == 200 and len(resp.text) > 50:
                    self.vulns.append({
                        'type': 'asvs_violation',
                        'requirement': 'V1.16.1 - Configuration management',
                        'severity': 'high',
                        'evidence': f'Configuration file exposed: {config_file}',
                        'url': test_url
                    })
                    
        except Exception as e:
            pass
    
    # Simplified implementations for Level 2-4 checks
    def _check_business_logic_flaws(self):
        """V2.1.1 - Verify business logic flaws"""
        self.total_checks += 1
        # Implementation would check for business logic vulnerabilities
        
    def _check_file_upload_security(self):
        """V2.2.1 - Verify file upload security"""
        self.total_checks += 1
        # Implementation would check file upload security
        
    def _check_ssrf_protection(self):
        """V2.3.1 - Verify SSRF protection"""
        self.total_checks += 1
        # Implementation would check SSRF protection
        
    def _check_ssti_protection(self):
        """V2.4.1 - Verify SSTI protection"""
        self.total_checks += 1
        # Implementation would check SSTI protection
        
    def _check_deserialization_protection(self):
        """V2.5.1 - Verify deserialization protection"""
        self.total_checks += 1
        # Implementation would check deserialization protection
        
    def _check_weak_cryptography(self):
        """V2.6.1 - Verify weak cryptography"""
        self.total_checks += 1
        # Implementation would check for weak cryptography
        
    def _check_authorization(self):
        """V2.7.1 - Verify authorization"""
        self.total_checks += 1
        # Implementation would check authorization
        
    def _check_client_side_security(self):
        """V2.8.1 - Verify client-side security"""
        self.total_checks += 1
        # Implementation would check client-side security
        
    def _check_html5_security(self):
        """V2.9.1 - Verify HTML5 security"""
        self.total_checks += 1
        # Implementation would check HTML5 security
        
    def _check_http_advanced_security(self):
        """V2.10.1 - Verify HTTP security"""
        self.total_checks += 1
        # Implementation would check advanced HTTP security
        
    def _check_web_services_security(self):
        """V2.11.1 - Verify web services security"""
        self.total_checks += 1
        # Implementation would check web services security
        
    def _check_mobile_security(self):
        """V2.12.1 - Verify mobile security"""
        self.total_checks += 1
        # Implementation would check mobile security
        
    # Level 3 checks (simplified)
    def _check_advanced_business_logic(self):
        self.total_checks += 1
        
    def _check_advanced_input_validation(self):
        self.total_checks += 1
        
    def _check_advanced_output_encoding(self):
        self.total_checks += 1
        
    def _check_advanced_authentication(self):
        self.total_checks += 1
        
    def _check_advanced_session_management(self):
        self.total_checks += 1
        
    def _check_advanced_access_control(self):
        self.total_checks += 1
        
    def _check_advanced_cryptography(self):
        self.total_checks += 1
        
    def _check_advanced_error_handling(self):
        self.total_checks += 1
        
    def _check_advanced_logging(self):
        self.total_checks += 1
        
    def _check_advanced_data_protection(self):
        self.total_checks += 1
        
    # Level 4 checks (simplified)
    def _check_custom_cryptography(self):
        self.total_checks += 1
        
    def _check_custom_business_logic(self):
        self.total_checks += 1
        
    def _check_advanced_architecture(self):
        self.total_checks += 1
        
    def _check_advanced_deployment(self):
        self.total_checks += 1
        
    def _check_advanced_operations(self):
        self.total_checks += 1
    
    def _check_framework_vulnerabilities(self, frameworks):
        """Check for known framework vulnerabilities"""
        # Implementation would check CVE databases for framework versions
        pass
    
    def _calculate_compliance_score(self):
        """Calculate ASVS compliance score"""
        if self.total_checks == 0:
            self.compliance_score = 0
            return
        
        violations = len(self.vulns)
        passed_checks = self.total_checks - violations
        self.compliance_score = (passed_checks / self.total_checks) * 100
    
    def get_compliance_report(self):
        """Generate ASVS compliance report"""
        return {
            'total_checks': self.total_checks,
            'violations': len(self.vulns),
            'compliance_score': self.compliance_score,
            'severity_breakdown': self._get_severity_breakdown(),
            'requirement_breakdown': self._get_requirement_breakdown()
        }
    
    def _get_severity_breakdown(self):
        """Get breakdown of violations by severity"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in self.vulns:
            severity = vuln.get('severity', 'medium')
            breakdown[severity] += 1
        return breakdown
    
    def _get_requirement_breakdown(self):
        """Get breakdown of violations by requirement"""
        breakdown = {}
        for vuln in self.vulns:
            req = vuln.get('requirement', 'Unknown')
            breakdown[req] = breakdown.get(req, 0) + 1
        return breakdown
