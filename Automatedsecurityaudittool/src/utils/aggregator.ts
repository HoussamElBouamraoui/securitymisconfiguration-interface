import type { NormalizedTarget, ScanResult, AggregatedResults, SeverityLevel } from '@/types/scan';
import { calculateRiskScore, calculateOverallSeverity } from './normalizer';

/**
 * Agrège les résultats de tous les modules de scan
 */
export function aggregateResults(
  target: NormalizedTarget,
  results: ScanResult[],
  metadata: {
    version: string;
    aggressiveness: 'passive' | 'normal' | 'aggressive';
    timeout: number;
  }
): AggregatedResults {
  const scanId = generateScanId();
  const timestamp = new Date();
  
  // Calcul de la durée totale
  const totalDuration = results.reduce((sum, r) => sum + (r.duration || 0), 0);
  
  // Calcul des statistiques
  const completedModules = results.filter(r => r.status === 'completed').length;
  const failedModules = results.filter(r => r.status === 'failed').length;
  
  const allFindings = results.flatMap(r => r.findings);
  const totalFindings = allFindings.length;
  
  // Comptage par sévérité
  const findingsBySeverity: Record<SeverityLevel, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  
  allFindings.forEach(finding => {
    findingsBySeverity[finding.severity]++;
  });
  
  // Calcul de la sévérité globale
  const overallSeverity = calculateOverallSeverity(
    results.map(r => r.severity)
  );
  
  // Calcul du score de risque
  const riskScore = calculateRiskScore(results);
  
  return {
    target,
    scanId,
    timestamp,
    totalDuration,
    overallSeverity,
    riskScore,
    summary: {
      totalModules: results.length,
      completedModules,
      failedModules,
      totalFindings,
      findingsBySeverity
    },
    results,
    metadata
  };
}

/**
 * Génère un identifiant unique pour le scan
 */
function generateScanId(): string {
  const timestamp = Date.now().toString(36);
  const randomStr = Math.random().toString(36).substring(2, 9);
  return `scan-${timestamp}-${randomStr}`;
}

/**
 * Filtre les résultats par sévérité minimale
 */
export function filterBySeverity(
  results: AggregatedResults,
  minSeverity: SeverityLevel
): AggregatedResults {
  const severityRank: Record<SeverityLevel, number> = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
  };
  
  const minRank = severityRank[minSeverity];
  
  const filteredResults = results.results.map(result => ({
    ...result,
    findings: result.findings.filter(f => severityRank[f.severity] >= minRank)
  })).filter(result => result.findings.length > 0);
  
  return aggregateResults(results.target, filteredResults, results.metadata);
}

/**
 * Génère un résumé exécutif
 */
export function generateExecutiveSummary(results: AggregatedResults): string {
  const { summary, riskScore, overallSeverity } = results;
  
  let summary_text = `Analyse de Sécurité - ${results.target.hostname}\n\n`;
  summary_text += `Score de Risque: ${riskScore}/100 (${overallSeverity.toUpperCase()})\n`;
  summary_text += `Modules exécutés: ${summary.completedModules}/${summary.totalModules}\n`;
  summary_text += `Constats totaux: ${summary.totalFindings}\n\n`;
  
  summary_text += `Répartition par sévérité:\n`;
  summary_text += `  • Critique: ${summary.findingsBySeverity.critical}\n`;
  summary_text += `  • Haute: ${summary.findingsBySeverity.high}\n`;
  summary_text += `  • Moyenne: ${summary.findingsBySeverity.medium}\n`;
  summary_text += `  • Basse: ${summary.findingsBySeverity.low}\n`;
  summary_text += `  • Info: ${summary.findingsBySeverity.info}\n`;
  
  return summary_text;
}
