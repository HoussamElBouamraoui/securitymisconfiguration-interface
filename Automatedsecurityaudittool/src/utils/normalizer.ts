import type { ScanResult, SeverityLevel, ConfidenceLevel } from '@/types/scan';

/**
 * Moteur de normalisation des résultats
 * Impose un schéma strict et recalcule les métriques de manière cohérente
 */
export function normalizeScanResult(result: ScanResult): ScanResult {
  // Vérification de la cohérence
  if (!result.moduleId || !result.moduleName) {
    throw new Error('Résultat de scan invalide: moduleId et moduleName requis');
  }
  
  // Recalcul de la sévérité basée sur les findings réels
  const recalculatedSeverity = calculateOverallSeverity(
    result.findings.map(f => f.severity)
  );
  
  // Recalcul de la confiance basée sur les findings
  const recalculatedConfidence = calculateOverallConfidence(
    result.findings.map(f => f.confidence)
  );
  
  // Calcul de la durée si non fournie
  const duration = result.duration || 
    (result.endTime && result.startTime 
      ? result.endTime.getTime() - result.startTime.getTime() 
      : 0);
  
  return {
    ...result,
    severity: recalculatedSeverity,
    confidence: recalculatedConfidence,
    duration,
    findings: result.findings.map((finding, index) => ({
      ...finding,
      id: finding.id || `${result.moduleId}-finding-${index}`
    }))
  };
}

/**
 * Calcule la sévérité globale à partir d'une liste de sévérités
 */
export function calculateOverallSeverity(severities: SeverityLevel[]): SeverityLevel {
  if (severities.length === 0) return 'info';
  
  const severityRank: Record<SeverityLevel, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
  };
  
  const maxRank = Math.max(...severities.map(s => severityRank[s]));
  
  const rankToSeverity: Record<number, SeverityLevel> = {
    5: 'critical',
    4: 'high',
    3: 'medium',
    2: 'low',
    1: 'info'
  };
  
  return rankToSeverity[maxRank];
}

/**
 * Calcule le niveau de confiance global
 */
export function calculateOverallConfidence(confidences: ConfidenceLevel[]): ConfidenceLevel {
  if (confidences.length === 0) return 'tentative';
  
  const confidenceRank: Record<ConfidenceLevel, number> = {
    certain: 3,
    firm: 2,
    tentative: 1
  };
  
  // Utilise la confiance minimale (principe de prudence)
  const minRank = Math.min(...confidences.map(c => confidenceRank[c]));
  
  const rankToConfidence: Record<number, ConfidenceLevel> = {
    3: 'certain',
    2: 'firm',
    1: 'tentative'
  };
  
  return rankToConfidence[minRank];
}

/**
 * Calcule un score de risque de 0 à 100
 */
export function calculateRiskScore(results: ScanResult[]): number {
  let totalScore = 0;
  let maxPossibleScore = 0;
  
  const severityWeights: Record<SeverityLevel, number> = {
    critical: 10,
    high: 7,
    medium: 4,
    low: 2,
    info: 0
  };
  
  const confidenceMultipliers: Record<ConfidenceLevel, number> = {
    certain: 1.0,
    firm: 0.7,
    tentative: 0.4
  };
  
  results.forEach(result => {
    result.findings.forEach(finding => {
      const baseScore = severityWeights[finding.severity];
      const multiplier = confidenceMultipliers[finding.confidence];
      totalScore += baseScore * multiplier;
      maxPossibleScore += 10; // Score max par finding
    });
  });
  
  if (maxPossibleScore === 0) return 0;
  
  return Math.round((totalScore / maxPossibleScore) * 100);
}

/**
 * Valide la cohérence d'un résultat de scan
 */
export function validateScanResult(result: ScanResult): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  if (!result.moduleId) errors.push('moduleId manquant');
  if (!result.moduleName) errors.push('moduleName manquant');
  if (!result.status) errors.push('status manquant');
  if (!result.startTime) errors.push('startTime manquant');
  
  if (result.status === 'completed' && !result.endTime) {
    errors.push('endTime requis pour un scan complété');
  }
  
  if (!Array.isArray(result.findings)) {
    errors.push('findings doit être un tableau');
  } else {
    result.findings.forEach((finding, index) => {
      if (!finding.id) errors.push(`Finding ${index}: id manquant`);
      if (!finding.title) errors.push(`Finding ${index}: title manquant`);
      if (!finding.severity) errors.push(`Finding ${index}: severity manquant`);
      if (!finding.confidence) errors.push(`Finding ${index}: confidence manquant`);
    });
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}
