import type { AggregatedResults } from '@/types/scan';
import { jsPDF } from 'jspdf';
// @ts-ignore
import autoTable from 'jspdf-autotable';

/**
 * Génère un rapport PDF à partir des résultats agrégés
 */
export function generatePDFReport(results: AggregatedResults): void {
  const doc = new jsPDF();
  
  let yPosition = 20;
  
  // En-tête
  doc.setFontSize(20);
  doc.setTextColor(40, 40, 40);
  doc.text('Rapport de Pentest Assistant', 14, yPosition);
  yPosition += 10;
  
  doc.setFontSize(12);
  doc.setTextColor(100, 100, 100);
  doc.text(`OWASP Top 10 A02: Security Misconfiguration`, 14, yPosition);
  yPosition += 15;
  
  // Informations générales
  doc.setFontSize(14);
  doc.setTextColor(40, 40, 40);
  doc.text('Informations du Scan', 14, yPosition);
  yPosition += 8;
  
  doc.setFontSize(10);
  doc.setTextColor(60, 60, 60);
  doc.text(`Cible: ${results.target.hostname}`, 14, yPosition);
  yPosition += 6;
  doc.text(`Date: ${results.timestamp.toLocaleString('fr-FR')}`, 14, yPosition);
  yPosition += 6;
  doc.text(`Durée totale: ${(results.totalDuration / 1000).toFixed(2)}s`, 14, yPosition);
  yPosition += 6;
  doc.text(`ID de scan: ${results.scanId}`, 14, yPosition);
  yPosition += 12;
  
  // Score de risque
  doc.setFontSize(14);
  doc.setTextColor(40, 40, 40);
  doc.text('Score de Risque Global', 14, yPosition);
  yPosition += 8;
  
  const scoreColor = getRiskScoreColor(results.riskScore);
  doc.setFontSize(24);
  doc.setTextColor(...scoreColor);
  doc.text(`${results.riskScore}/100`, 14, yPosition);
  
  doc.setFontSize(12);
  doc.text(`(${results.overallSeverity.toUpperCase()})`, 50, yPosition);
  yPosition += 15;
  
  // Tableau de synthèse
  doc.setFontSize(14);
  doc.setTextColor(40, 40, 40);
  doc.text('Synthèse des Constats', 14, yPosition);
  yPosition += 5;
  
  const summaryData = [
    ['Critique', results.summary.findingsBySeverity.critical.toString()],
    ['Haute', results.summary.findingsBySeverity.high.toString()],
    ['Moyenne', results.summary.findingsBySeverity.medium.toString()],
    ['Basse', results.summary.findingsBySeverity.low.toString()],
    ['Info', results.summary.findingsBySeverity.info.toString()],
    ['Total', results.summary.totalFindings.toString()]
  ];
  
  autoTable(doc, {
    startY: yPosition,
    head: [['Sévérité', 'Nombre']],
    body: summaryData,
    theme: 'striped',
    headStyles: { fillColor: [41, 128, 185] },
    margin: { left: 14, right: 14 }
  });
  
  yPosition = (doc as any).lastAutoTable.finalY + 15;
  
  // Détails par module
  doc.addPage();
  yPosition = 20;
  
  doc.setFontSize(16);
  doc.setTextColor(40, 40, 40);
  doc.text('Détails des Constats', 14, yPosition);
  yPosition += 10;
  
  results.results.forEach((result, index) => {
    if (result.findings.length === 0) return;
    
    // Vérifier si on a besoin d'une nouvelle page
    if (yPosition > 250) {
      doc.addPage();
      yPosition = 20;
    }
    
    doc.setFontSize(12);
    doc.setTextColor(40, 40, 40);
    doc.text(`${index + 1}. ${result.moduleName}`, 14, yPosition);
    yPosition += 6;
    
    doc.setFontSize(10);
    doc.setTextColor(100, 100, 100);
    doc.text(`Sévérité: ${result.severity.toUpperCase()} | Constats: ${result.findings.length}`, 14, yPosition);
    yPosition += 8;
    
    // Tableau des findings pour ce module
    const findingsData = result.findings.map(f => [
      f.title,
      f.severity.toUpperCase(),
      f.confidence
    ]);
    
    autoTable(doc, {
      startY: yPosition,
      head: [['Constat', 'Sévérité', 'Confiance']],
      body: findingsData,
      theme: 'plain',
      styles: { fontSize: 9 },
      headStyles: { fillColor: [52, 73, 94], textColor: 255 },
      margin: { left: 14, right: 14 },
      columnStyles: {
        0: { cellWidth: 100 },
        1: { cellWidth: 40 },
        2: { cellWidth: 40 }
      }
    });
    
    yPosition = (doc as any).lastAutoTable.finalY + 10;
  });
  
  // Recommandations générales
  doc.addPage();
  yPosition = 20;
  
  doc.setFontSize(16);
  doc.setTextColor(40, 40, 40);
  doc.text('Recommandations Prioritaires', 14, yPosition);
  yPosition += 10;
  
  const criticalFindings = results.results
    .flatMap(r => r.findings)
    .filter(f => f.severity === 'critical' || f.severity === 'high')
    .slice(0, 10);
  
  if (criticalFindings.length > 0) {
    doc.setFontSize(10);
    criticalFindings.forEach((finding, index) => {
      if (yPosition > 270) {
        doc.addPage();
        yPosition = 20;
      }
      
      doc.setTextColor(40, 40, 40);
      doc.text(`${index + 1}. ${finding.title}`, 14, yPosition);
      yPosition += 6;
      
      doc.setTextColor(100, 100, 100);
      const recommendation = finding.recommendation || 'Aucune recommandation spécifique';
      const lines = doc.splitTextToSize(recommendation, 180);
      doc.text(lines, 20, yPosition);
      yPosition += (lines.length * 5) + 8;
    });
  } else {
    doc.setFontSize(10);
    doc.setTextColor(40, 180, 40);
    doc.text('Aucun constat critique ou haute sévérité détecté.', 14, yPosition);
  }
  
  // Footer sur toutes les pages
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setTextColor(150, 150, 150);
    doc.text(
      `Page ${i} / ${pageCount}`,
      doc.internal.pageSize.getWidth() / 2,
      doc.internal.pageSize.getHeight() - 10,
      { align: 'center' }
    );
    doc.text(
      'Généré par Pentest Assistant v1.0.0',
      14,
      doc.internal.pageSize.getHeight() - 10
    );
  }
  
  // Téléchargement
  doc.save(`pentest-${results.scanId}.pdf`);
}

function getRiskScoreColor(score: number): [number, number, number] {
  if (score >= 70) return [231, 76, 60];  // Rouge
  if (score >= 40) return [230, 126, 34]; // Orange
  if (score >= 20) return [241, 196, 15]; // Jaune
  return [46, 204, 113];                  // Vert
}
