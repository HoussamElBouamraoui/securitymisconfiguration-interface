import { useState } from 'react';
import { Terminal, type TerminalLine } from './components/Terminal';
import { ScanProgress } from './components/ScanProgress';
import { ScanResults } from './components/ScanResults';
import type { AggregatedResults } from '../types/scan';
import { runA02Scan, mapRunnerJsonToAggregatedResults, runA02SingleScan, getA02ScansList } from '../utils/a02-api';

export default function App() {
  const [lines, setLines] = useState<TerminalLine[]>([
    {
      type: 'success',
      content: 'Pentest Assistant v1.0.0 - OWASP Top 10 A02 Security Misconfiguration Scanner',
      timestamp: new Date()
    },
    {
      type: 'info',
      content: 'Type "help" pour voir les commandes disponibles',
      timestamp: new Date()
    },
    {
      type: 'info',
      content: 'Backend requis: démarrez l’API Python sur http://127.0.0.1:8000',
      timestamp: new Date()
    }
    {
     type:'login',
     content:''
    }
  ]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [scanResults, setScanResults] = useState<AggregatedResults | null>(null);
  const [scanStartedAt, setScanStartedAt] = useState<Date | null>(null);

  const addLine = (line: Omit<TerminalLine, 'timestamp'>) => {
    setLines(prev => [...prev, { ...line, timestamp: new Date() }]);
  };

  const handleCommand = (command: string) => {
    addLine({ type: 'input', content: command });

    const parts = command.split(' ');
    const cmd = parts[0].toLowerCase();
    const args = parts.slice(1);

    switch (cmd) {
      case 'help':
        handleHelp();
        break;
      case 'scan':
        if (args.length === 0) {
          addLine({ type: 'error', content: 'Usage: scan <target>' });
        } else {
          handleScan(args[0]);
        }
        break;
      case 'scans':
        handleListScans();
        break;
      case 'scanmod':
        if (args.length < 2) {
          addLine({ type: 'error', content: 'Usage: scanmod <module> <target>' });
          addLine({ type: 'info', content: 'Ex: scanmod port_scanner_aggressive 127.0.0.1' });
        } else {
          handleSingleModuleScan(args[0], args[1]);
        }
        break;
      case 'clear':
        setLines([]);
        break;
      case 'version':
        addLine({ type: 'info', content: 'Pentest Assistant v1.0.0' });
        break;
      default:
        addLine({ type: 'error', content: `Commande inconnue: ${cmd}. Tapez "help" pour l'aide.` });
    }
  };

  const handleHelp = () => {
    const helpText = [
      '=============================================================================',
      'Commandes disponibles:',
      '  scan <target>     Lance un scan A02 sur la cible via l\'API Python locale',
      '                    Ex: scan example.com ou scan https://example.com',
      '  scanmod <module> <target>  Lance un module A02 spécifique (sous-scan)',
      '                    Ex: scanmod port_scanner_aggressive 127.0.0.1',
      '  scans             Affiche la liste des sous-scans/modules disponibles',
      '  clear             Efface le terminal',
      '  version           Affiche la version',
      '  help              Affiche cette aide',
      '============================================================================='
    ];

    helpText.forEach(text => {
      addLine({ type: 'output', content: text });
    });
  };

  const handleScan = (targetStr: string) => {
    setIsProcessing(true);
    setScanStartedAt(new Date());

    addLine({ type: 'info', content: `Envoi du scan à l\'API (target=${targetStr})...` });

    // Timeline "optimiste": on montre les 16 sous-scans attendus comme "Running".
    // (Sans endpoint async, on ne peut pas faire un vrai progress temps réel; c'est déjà un gros mieux UX.)
    setScanResults({
      scanId: crypto.randomUUID(),
      target: { raw: targetStr, type: 'hostname', hostname: targetStr },
      timestamp: new Date(),
      totalDuration: 0,
      overallSeverity: 'info',
      riskScore: 0,
      summary: {
        totalModules: 16,
        completedModules: 0,
        failedModules: 0,
        totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
      },
      results: Array.from({ length: 16 }).map((_, i) => ({
        moduleId: `A02_Module_${i + 1}`,
        moduleName: `A02 Module #${i + 1}`,
        status: 'started',
        startTime: new Date(),
        endTime: new Date(),
        duration: 0,
        severity: 'info',
        confidence: 'tentative',
        findings: []
      })),
      metadata: { version: '1.0.0', aggressiveness: 'normal', timeout: 30000 }
    });

    runA02Scan({
      target: targetStr,
      connectTimeout: 3,
      readTimeout: 6,
      retries: 1,
      perScanTimebox: 120,
      turbo: false,
      generatePdf: true
    })
      .then((data) => {
        const aggregated = mapRunnerJsonToAggregatedResults(targetStr, data);
        setScanResults(aggregated);

        addLine({ type: 'success', content: 'Scan terminé avec succès (via API)!' });
        addLine({ type: 'info', content: `Score de risque: ${aggregated.riskScore}/100 (${aggregated.overallSeverity.toUpperCase()})` });
        addLine({ type: 'info', content: `Constats trouvés: ${aggregated.summary.totalFindings}` });
        if (aggregated.artifacts?.pdf) {
          addLine({ type: 'success', content: 'PDF généré côté serveur (bouton Export PDF disponible)' });
        } else {
          addLine({ type: 'error', content: 'PDF non généré côté serveur. Vérifiez le backend (logs) et relancez le scan.' });
        }
      })
      .catch((error) => {
        addLine({
          type: 'error',
          content: error instanceof Error ? error.message : 'Erreur inconnue'
        });
      })
      .finally(() => {
        setIsProcessing(false);
      });
  };

  const handleSingleModuleScan = (moduleId: string, targetStr: string) => {
    setIsProcessing(true);
    setScanStartedAt(new Date());

    addLine({ type: 'info', content: `Envoi du sous-scan à l\'API (scan=${moduleId}, target=${targetStr})...` });
    addLine({ type: 'info', content: 'Note: le PDF est généré uniquement lors de la commande "scan" (full scan), pas via "scanmod".' });

    // Timeline optimiste: un seul module en cours.
    setScanResults({
      scanId: crypto.randomUUID(),
      target: { raw: targetStr, type: 'hostname', hostname: targetStr },
      timestamp: new Date(),
      totalDuration: 0,
      overallSeverity: 'info',
      riskScore: 0,
      summary: {
        totalModules: 1,
        completedModules: 0,
        failedModules: 0,
        totalFindings: 0,
        findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
      },
      results: [
        {
          moduleId,
          moduleName: moduleId,
          status: 'started',
          startTime: new Date(),
          endTime: new Date(),
          duration: 0,
          severity: 'info',
          confidence: 'tentative',
          findings: []
        }
      ],
      metadata: { version: '1.0.0', aggressiveness: 'normal', timeout: 30000 }
    });

    runA02SingleScan({
      target: targetStr,
      scan: moduleId,
      connectTimeout: 3,
      readTimeout: 6,
      retries: 1,
      perScanTimebox: 120
    })
      .then((data) => {
        const aggregated = mapRunnerJsonToAggregatedResults(targetStr, data);
        setScanResults(aggregated);
        addLine({ type: 'success', content: `Sous-scan terminé (${moduleId})` });
        addLine({ type: 'info', content: `Constats trouvés: ${aggregated.summary.totalFindings}` });
        addLine({ type: 'info', content: 'PDF: non disponible en mode "scanmod". Utilisez "scan <target>" pour générer un PDF.' });
      })
      .catch((error) => {
        addLine({ type: 'error', content: error instanceof Error ? error.message : 'Erreur inconnue' });
      })
      .finally(() => {
        setIsProcessing(false);
      });
  };

  const handleExportJSON = () => {
    if (!scanResults) return;

    const json = JSON.stringify(scanResults, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pentest-${scanResults.scanId}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    addLine({ type: 'success', content: 'Rapport JSON exporté' });
  };

  const handleExportPDF = () => {
    if (!scanResults?.artifacts?.pdf) {
      addLine({ type: 'error', content: 'Aucun PDF disponible. Relancez un scan (PDF généré côté serveur).' });
      return;
    }

    const url = `/api${scanResults.artifacts.pdf}`;
    const a = document.createElement('a');
    a.href = url;
    a.download = `pentest-${scanResults.scanId}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

    addLine({ type: 'success', content: 'Téléchargement du PDF lancé' });
  };

  const handleListScans = () => {
    addLine({ type: 'info', content: 'Récupération de la liste des sous-scans depuis l\'API…' });
    getA02ScansList()
      .then((data) => {
        addLine({ type: 'success', content: `Sous-scans disponibles (${data.count}) :` });
        data.scans.forEach((s) => addLine({ type: 'output', content: `  - ${s}` }));
        addLine({ type: 'info', content: 'Exemple: scanmod port_scanner_aggressive 127.0.0.1' });
      })
      .catch((error) => {
        addLine({ type: 'error', content: error instanceof Error ? error.message : 'Erreur inconnue' });
      });
  };

  return (
    <div className="h-screen w-screen overflow-hidden bg-[#0d1117] flex">
      {/* Colonne gauche: fixe (pas de scroll global) */}
      <div className="w-1/2 p-4 border-r border-[#30363d] h-full overflow-hidden">
        <Terminal
          onCommand={handleCommand}
          lines={lines}
          isProcessing={isProcessing}
        />
      </div>

      {/* Colonne droite: scrollable uniquement ici */}
      <div className="w-1/2 h-full overflow-hidden">
        <div className="h-full overflow-y-auto">
          <div className="p-4 space-y-4">
            {scanResults && (
              <ScanProgress
                results={scanResults.results}
                isScanning={isProcessing}
                startedAt={scanStartedAt ?? undefined}
              />
            )}
          </div>

          <ScanResults
            results={scanResults}
            onExportJSON={handleExportJSON}
            onExportPDF={handleExportPDF}
          />
        </div>
      </div>
    </div>
  );
}