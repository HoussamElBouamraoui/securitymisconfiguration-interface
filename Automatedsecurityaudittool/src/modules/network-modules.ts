import type { ScanModule, NormalizedTarget, ScanResult, Finding } from '@/types/scan';

/**
 * Module de scan des ports ouverts et services exposés
 */
export const portScanModule: ScanModule = {
  id: 'network-port-scan',
  name: 'Scan des Ports',
  description: 'Identifie les ports ouverts et les services exposés',
  category: 'network',
  execute: async (target: NormalizedTarget): Promise<ScanResult> => {
    const startTime = new Date();
    const findings: Finding[] = [];
    
    // Simulation de scan de ports communs
    const commonPorts = [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080, 8443];
    const openPorts = commonPorts.filter(() => Math.random() > 0.7); // Simulation
    
    for (const port of openPorts) {
      const serviceInfo = getServiceInfo(port);
      
      findings.push({
        id: `port-${port}`,
        title: `Port ${port} ouvert (${serviceInfo.name})`,
        description: `Le port ${port} est accessible depuis l'extérieur. Service détecté: ${serviceInfo.name}`,
        severity: serviceInfo.severity,
        confidence: 'firm',
        evidence: `Port: ${port}, Service: ${serviceInfo.name}`,
        recommendation: serviceInfo.recommendation,
        cwe: 'CWE-16',
        owasp: 'A02:2021 - Cryptographic Failures'
      });
    }
    
    // Vérification de services obsolètes
    const dangerousPorts = [21, 23, 445];
    const exposedDangerousPorts = openPorts.filter(p => dangerousPorts.includes(p));
    
    if (exposedDangerousPorts.length > 0) {
      findings.push({
        id: 'obsolete-services',
        title: 'Services obsolètes ou dangereux exposés',
        description: `Des services connus pour leurs failles de sécurité sont exposés: ${exposedDangerousPorts.join(', ')}`,
        severity: 'high',
        confidence: 'certain',
        evidence: `Ports dangereux: ${exposedDangerousPorts.join(', ')}`,
        recommendation: 'Désactiver les services obsolètes (FTP, Telnet, SMB direct) et utiliser des alternatives sécurisées.',
        cwe: 'CWE-1188',
        owasp: 'A02:2021 - Security Misconfiguration'
      });
    }
    
    const endTime = new Date();
    const highestSeverity = findings.reduce((max, f) => {
      const severityRank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
      return severityRank[f.severity] > severityRank[max] ? f.severity : max;
    }, 'info' as const);
    
    return {
      moduleId: 'network-port-scan',
      moduleName: 'Scan des Ports',
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
 * Module de scan des bannières de services
 */
export const bannerGrabbingModule: ScanModule = {
  id: 'network-banner-grabbing',
  name: 'Analyse des Bannières',
  description: 'Collecte et analyse les bannières de services pour détecter les fuites d\'information',
  category: 'network',
  execute: async (target: NormalizedTarget): Promise<ScanResult> => {
    const startTime = new Date();
    const findings: Finding[] = [];
    
    // Simulation de bannières révélatrices
    const banners = [
      {
        service: 'SSH',
        banner: 'SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7',
        port: 22
      },
      {
        service: 'HTTP',
        banner: 'Server: Apache/2.4.29 (Ubuntu)',
        port: 80
      }
    ];
    
    if (Math.random() > 0.5) {
      banners.forEach(banner => {
        findings.push({
          id: `banner-${banner.port}`,
          title: `Bannière révélatrice détectée (${banner.service})`,
          description: `Le service ${banner.service} expose des informations détaillées sur sa version`,
          severity: 'low',
          confidence: 'certain',
          evidence: banner.banner,
          recommendation: 'Masquer ou minimiser les informations de version dans les bannières de service.',
          cwe: 'CWE-200',
          owasp: 'A02:2021 - Security Misconfiguration'
        });
      });
    }
    
    const endTime = new Date();
    
    return {
      moduleId: 'network-banner-grabbing',
      moduleName: 'Analyse des Bannières',
      status: 'completed',
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      severity: findings.length > 0 ? 'low' : 'info',
      confidence: 'certain',
      findings
    };
  }
};

function getServiceInfo(port: number) {
  const services: Record<number, { name: string; severity: 'critical' | 'high' | 'medium' | 'low' | 'info'; recommendation: string }> = {
    21: {
      name: 'FTP',
      severity: 'high',
      recommendation: 'Utiliser SFTP ou FTPS à la place de FTP non chiffré'
    },
    22: {
      name: 'SSH',
      severity: 'medium',
      recommendation: 'S\'assurer que l\'authentification par clé est activée et que les mots de passe faibles sont interdits'
    },
    23: {
      name: 'Telnet',
      severity: 'critical',
      recommendation: 'Remplacer Telnet par SSH immédiatement'
    },
    25: {
      name: 'SMTP',
      severity: 'medium',
      recommendation: 'Vérifier que le relay ouvert est désactivé'
    },
    80: {
      name: 'HTTP',
      severity: 'low',
      recommendation: 'Rediriger tout le trafic HTTP vers HTTPS'
    },
    443: {
      name: 'HTTPS',
      severity: 'info',
      recommendation: 'Vérifier la configuration TLS et les certificats'
    },
    445: {
      name: 'SMB',
      severity: 'high',
      recommendation: 'Ne pas exposer SMB sur Internet, utiliser un VPN'
    },
    3306: {
      name: 'MySQL',
      severity: 'critical',
      recommendation: 'Ne jamais exposer les bases de données directement, utiliser un VPN ou bastion'
    },
    3389: {
      name: 'RDP',
      severity: 'high',
      recommendation: 'Ne pas exposer RDP sur Internet, utiliser un VPN'
    },
    5432: {
      name: 'PostgreSQL',
      severity: 'critical',
      recommendation: 'Ne jamais exposer les bases de données directement, utiliser un VPN ou bastion'
    },
    8080: {
      name: 'HTTP Alt',
      severity: 'low',
      recommendation: 'Vérifier si ce service devrait être exposé publiquement'
    },
    8443: {
      name: 'HTTPS Alt',
      severity: 'low',
      recommendation: 'Vérifier la configuration TLS'
    }
  };
  
  return services[port] || {
    name: 'Unknown',
    severity: 'medium',
    recommendation: 'Identifier le service et évaluer la nécessité de son exposition'
  };
}
