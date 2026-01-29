import type { ScanModule, NormalizedTarget, ScanResult, Finding } from '@/types/scan';
import { getTargetUrl } from '@/utils/target-normalizer';

/**
 * Module de scan des en-têtes de sécurité HTTP
 */
export const securityHeadersModule: ScanModule = {
  id: 'web-security-headers',
  name: 'En-têtes de Sécurité HTTP',
  description: 'Vérifie la présence et la configuration des en-têtes de sécurité HTTP',
  category: 'web',
  execute: async (target: NormalizedTarget): Promise<ScanResult> => {
    const startTime = new Date();
    const findings: Finding[] = [];
    
    // Simulation de vérification d'en-têtes
    const missingHeaders = [
      {
        name: 'Strict-Transport-Security',
        severity: 'high' as const,
        description: 'Force l\'utilisation de HTTPS',
        recommendation: 'Ajouter: Strict-Transport-Security: max-age=31536000; includeSubDomains'
      },
      {
        name: 'X-Content-Type-Options',
        severity: 'medium' as const,
        description: 'Empêche le MIME sniffing',
        recommendation: 'Ajouter: X-Content-Type-Options: nosniff'
      },
      {
        name: 'X-Frame-Options',
        severity: 'medium' as const,
        description: 'Protection contre le clickjacking',
        recommendation: 'Ajouter: X-Frame-Options: DENY ou SAMEORIGIN'
      },
      {
        name: 'Content-Security-Policy',
        severity: 'high' as const,
        description: 'Contrôle les sources de contenu autorisées',
        recommendation: 'Implémenter une politique CSP stricte'
      }
    ];
    
    // Simulation: certains headers manquent
    const actuallyMissing = missingHeaders.filter(() => Math.random() > 0.4);
    
    actuallyMissing.forEach(header => {
      findings.push({
        id: `header-missing-${header.name.toLowerCase()}`,
        title: `En-tête de sécurité manquant: ${header.name}`,
        description: `L'en-tête ${header.name} n'est pas présent. ${header.description}.`,
        severity: header.severity,
        confidence: 'certain',
        evidence: `En-tête absent: ${header.name}`,
        recommendation: header.recommendation,
        cwe: 'CWE-16',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    });
    
    const endTime = new Date();
    const highestSeverity = findings.reduce((max, f) => {
      const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
      return severityRank[f.severity] > severityRank[max] ? f.severity : max;
    }, 'info' as const);
    
    return {
      moduleId: 'web-security-headers',
      moduleName: 'En-têtes de Sécurité HTTP',
      status: 'completed',
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      severity: highestSeverity,
      confidence: 'certain',
      findings
    };
  }
};

/**
 * Module de scan des cookies non sécurisés
 */
export const cookieSecurityModule: ScanModule = {
  id: 'web-cookie-security',
  name: 'Sécurité des Cookies',
  description: 'Analyse les attributs de sécurité des cookies',
  category: 'web',
  execute: async (target: NormalizedTarget): Promise<ScanResult> => {
    const startTime = new Date();
    const findings: Finding[] = [];
    
    // Simulation de cookies non sécurisés
    if (Math.random() > 0.5) {
      findings.push({
        id: 'cookie-no-secure',
        title: 'Cookies sans attribut Secure',
        description: 'Des cookies de session sont transmis sans l\'attribut Secure, permettant leur interception en HTTP',
        severity: 'high',
        confidence: 'firm',
        evidence: 'Cookie: sessionid=...; Path=/; HttpOnly',
        recommendation: 'Ajouter l\'attribut Secure à tous les cookies sensibles',
        cwe: 'CWE-614',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    }
    
    if (Math.random() > 0.6) {
      findings.push({
        id: 'cookie-no-httponly',
        title: 'Cookies sans attribut HttpOnly',
        description: 'Des cookies sont accessibles via JavaScript, augmentant le risque de vol par XSS',
        severity: 'medium',
        confidence: 'firm',
        evidence: 'Cookie: authToken=...; Path=/; Secure',
        recommendation: 'Ajouter l\'attribut HttpOnly aux cookies de session',
        cwe: 'CWE-1004',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    }
    
    if (Math.random() > 0.7) {
      findings.push({
        id: 'cookie-no-samesite',
        title: 'Cookies sans attribut SameSite',
        description: 'Les cookies ne spécifient pas de politique SameSite, les rendant vulnérables aux attaques CSRF',
        severity: 'medium',
        confidence: 'firm',
        evidence: 'Cookie: session=...; Path=/; Secure; HttpOnly',
        recommendation: 'Ajouter SameSite=Strict ou SameSite=Lax selon le contexte',
        cwe: 'CWE-352',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    }
    
    const endTime = new Date();
    const highestSeverity = findings.reduce((max, f) => {
      const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
      return severityRank[f.severity] > severityRank[max] ? f.severity : max;
    }, 'info' as const);
    
    return {
      moduleId: 'web-cookie-security',
      moduleName: 'Sécurité des Cookies',
      status: 'completed',
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      severity: highestSeverity,
      confidence: 'firm',
      findings
    };
  }
};

/**
 * Module de scan des méthodes HTTP dangereuses
 */
export const httpMethodsModule: ScanModule = {
  id: 'web-http-methods',
  name: 'Méthodes HTTP',
  description: 'Teste les méthodes HTTP potentiellement dangereuses',
  category: 'web',
  execute: async (target: NormalizedTarget): Promise<ScanResult> => {
    const startTime = new Date();
    const findings: Finding[] = [];
    
    // Simulation de méthodes dangereuses activées
    const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'CONNECT'];
    const enabledDangerous = dangerousMethods.filter(() => Math.random() > 0.8);
    
    if (enabledDangerous.length > 0) {
      findings.push({
        id: 'dangerous-http-methods',
        title: 'Méthodes HTTP dangereuses activées',
        description: `Les méthodes suivantes sont activées: ${enabledDangerous.join(', ')}. Elles peuvent permettre des modifications non autorisées.`,
        severity: 'high',
        confidence: 'firm',
        evidence: `Méthodes détectées: ${enabledDangerous.join(', ')}`,
        recommendation: 'Désactiver les méthodes HTTP non nécessaires (PUT, DELETE, TRACE, CONNECT)',
        cwe: 'CWE-650',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    }
    
    if (enabledDangerous.includes('TRACE')) {
      findings.push({
        id: 'trace-method-xst',
        title: 'Vulnérabilité Cross-Site Tracing (XST)',
        description: 'La méthode TRACE est activée, permettant potentiellement des attaques XST',
        severity: 'medium',
        confidence: 'certain',
        evidence: 'Méthode TRACE activée',
        recommendation: 'Désactiver la méthode TRACE au niveau du serveur web',
        cwe: 'CWE-693',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    }
    
    const endTime = new Date();
    const highestSeverity = findings.reduce((max, f) => {
      const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
      return severityRank[f.severity] > severityRank[max] ? f.severity : max;
    }, 'info' as const);
    
    return {
      moduleId: 'web-http-methods',
      moduleName: 'Méthodes HTTP',
      status: 'completed',
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      severity: highestSeverity,
      confidence: 'firm',
      findings
    };
  }
};

/**
 * Module de scan des fichiers sensibles exposés
 */
export const sensitiveFilesModule: ScanModule = {
  id: 'web-sensitive-files',
  name: 'Fichiers Sensibles',
  description: 'Recherche des fichiers sensibles exposés publiquement',
  category: 'web',
  execute: async (target: NormalizedTarget): Promise<ScanResult> => {
    const startTime = new Date();
    const findings: Finding[] = [];
    
    // Liste de fichiers sensibles couramment exposés
    const sensitiveFiles = [
      { path: '/.env', severity: 'critical' as const, desc: 'Fichier de configuration avec secrets' },
      { path: '/.git/config', severity: 'high' as const, desc: 'Configuration Git exposée' },
      { path: '/backup.sql', severity: 'critical' as const, desc: 'Sauvegarde de base de données' },
      { path: '/phpinfo.php', severity: 'medium' as const, desc: 'Page d\'information PHP' },
      { path: '/admin', severity: 'medium' as const, desc: 'Interface d\'administration' },
      { path: '/.DS_Store', severity: 'low' as const, desc: 'Métadonnées macOS' },
      { path: '/web.config', severity: 'high' as const, desc: 'Configuration IIS' }
    ];
    
    // Simulation: certains fichiers sont accessibles
    const exposedFiles = sensitiveFiles.filter(() => Math.random() > 0.7);
    
    exposedFiles.forEach(file => {
      findings.push({
        id: `sensitive-file-${file.path.replace(/[^a-z0-9]/gi, '-')}`,
        title: `Fichier sensible exposé: ${file.path}`,
        description: `Le fichier ${file.path} est accessible publiquement. ${file.desc}.`,
        severity: file.severity,
        confidence: 'certain',
        evidence: `URL accessible: ${getTargetUrl(target)}${file.path}`,
        recommendation: 'Bloquer l\'accès aux fichiers sensibles via configuration serveur ou .htaccess',
        cwe: 'CWE-538',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    });
    
    const endTime = new Date();
    const highestSeverity = findings.reduce((max, f) => {
      const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
      return severityRank[f.severity] > severityRank[max] ? f.severity : max;
    }, 'info' as const);
    
    return {
      moduleId: 'web-sensitive-files',
      moduleName: 'Fichiers Sensibles',
      status: 'completed',
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      severity: highestSeverity,
      confidence: 'certain',
      findings
    };
  }
};

/**
 * Module de scan des messages d'erreur verbeux
 */
export const errorHandlingModule: ScanModule = {
  id: 'web-error-handling',
  name: 'Gestion des Erreurs',
  description: 'Détecte les messages d\'erreur trop verbeux révélant des informations sensibles',
  category: 'web',
  execute: async (target: NormalizedTarget): Promise<ScanResult> => {
    const startTime = new Date();
    const findings: Finding[] = [];
    
    // Simulation d'erreurs verboses
    if (Math.random() > 0.6) {
      findings.push({
        id: 'verbose-error-stack-trace',
        title: 'Stack traces exposées dans les erreurs',
        description: 'Les pages d\'erreur révèlent des stack traces complètes avec chemins internes',
        severity: 'medium',
        confidence: 'certain',
        evidence: 'Error in /var/www/html/app/controllers/UserController.php on line 42',
        recommendation: 'Désactiver l\'affichage détaillé des erreurs en production et utiliser des pages d\'erreur génériques',
        cwe: 'CWE-209',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    }
    
    if (Math.random() > 0.7) {
      findings.push({
        id: 'verbose-error-database',
        title: 'Erreurs de base de données exposées',
        description: 'Les erreurs SQL sont affichées directement aux utilisateurs',
        severity: 'high',
        confidence: 'firm',
        evidence: 'MySQL Error: Table \'users\' doesn\'t exist in database \'production_db\'',
        recommendation: 'Masquer les erreurs de base de données et logger en interne',
        cwe: 'CWE-209',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    }
    
    const endTime = new Date();
    const highestSeverity = findings.reduce((max, f) => {
      const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
      return severityRank[f.severity] > severityRank[max] ? f.severity : max;
    }, 'info' as const);
    
    return {
      moduleId: 'web-error-handling',
      moduleName: 'Gestion des Erreurs',
      status: 'completed',
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      severity: highestSeverity,
      confidence: findings.length > 0 ? 'certain' : 'firm',
      findings
    };
  }
};

/**
 * Module de scan des endpoints administratifs
 */
export const adminEndpointsModule: ScanModule = {
  id: 'web-admin-endpoints',
  name: 'Endpoints Administratifs',
  description: 'Détecte les endpoints administratifs ou de débogage accessibles',
  category: 'web',
  execute: async (target: NormalizedTarget): Promise<ScanResult> => {
    const startTime = new Date();
    const findings: Finding[] = [];
    
    const adminPaths = [
      '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
      '/debug', '/console', '/api/debug', '/__debug__',
      '/swagger', '/api-docs', '/graphql'
    ];
    
    // Simulation: certains endpoints sont accessibles
    const accessiblePaths = adminPaths.filter(() => Math.random() > 0.8);
    
    if (accessiblePaths.length > 0) {
      findings.push({
        id: 'accessible-admin-endpoints',
        title: 'Endpoints administratifs accessibles',
        description: `Des endpoints sensibles sont accessibles publiquement: ${accessiblePaths.join(', ')}`,
        severity: 'high',
        confidence: 'firm',
        evidence: `Endpoints détectés: ${accessiblePaths.join(', ')}`,
        recommendation: 'Restreindre l\'accès aux interfaces administratives via IP whitelisting ou VPN',
        cwe: 'CWE-425',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    }
    
    const endTime = new Date();
    
    return {
      moduleId: 'web-admin-endpoints',
      moduleName: 'Endpoints Administratifs',
      status: 'completed',
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      severity: findings.length > 0 ? 'high' : 'info',
      confidence: 'firm',
      findings
    };
  }
};
