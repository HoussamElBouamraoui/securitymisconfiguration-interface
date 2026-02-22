import type { AggregatedResults, Finding, SeverityLevel } from '../../types/scan';
import { fetchArtifact } from '../../utils/a02-api';
import JSZip from 'jszip';
import { AlertTriangle, CheckCircle, Info, XCircle, Shield } from 'lucide-react';
import { useState } from 'react';

interface ScanResultsProps {
  results: AggregatedResults | null;
  onExportJSON: () => void;
  onExportPDF: () => void;
}

export function ScanResults({ results, onExportJSON, onExportPDF }: ScanResultsProps) {
  if (!results) {
    return (
      <div className="h-full flex items-center justify-center text-[#7d8590]">
        <div className="text-center">
          <Shield className="w-16 h-16 mx-auto mb-4 opacity-50" />
          <p>Aucun résultat de scan disponible</p>
          <p className="text-sm mt-2">Lancez un scan pour voir les résultats ici</p>
        </div>
      </div>
    );
  }
  
  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'text-[#ff5f56]',
      high: 'text-[#ff9500]',
      medium: 'text-[#ffd60a]',
      low: 'text-[#32d74b]',
      info: 'text-[#58a6ff]'
    };
    return colors[severity] || 'text-[#7d8590]';
  };
  
  const getSeverityBgColor = (severity: string) => {
    const colors: Record<string, string> = {
      critical: 'bg-[#ff5f56]/10 border-[#ff5f56]/30',
      high: 'bg-[#ff9500]/10 border-[#ff9500]/30',
      medium: 'bg-[#ffd60a]/10 border-[#ffd60a]/30',
      low: 'bg-[#32d74b]/10 border-[#32d74b]/30',
      info: 'bg-[#58a6ff]/10 border-[#58a6ff]/30'
    };
    return colors[severity] || 'bg-[#30363d]/10 border-[#30363d]/30';
  };
  
  const getRiskScoreColor = (score: number) => {
    if (score >= 70) return 'text-[#ff5f56]';
    if (score >= 40) return 'text-[#ff9500]';
    if (score >= 20) return 'text-[#ffd60a]';
    return 'text-[#32d74b]';
  };
  
  const isTechnicalError = (r: any) => r.status === 'failed';
  const isTimeout = (r: any) => r.status === 'timeout';

  const technicalIssues = results.results.filter((r) => isTechnicalError(r) || isTimeout(r));

  const handleOpenExploitGuide = async () => {
    const p = results.artifacts?.exploitation_guide;
    if (!p) return;

    const resp = await fetchArtifact(p);
    if (!resp) {
      alert('Erreur: impossible de télécharger le guide.');
      return;
    }

    const blob = await resp.blob();
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `pentest-${results.scanId}-EXPLOITATION_GUIDE.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  };

  // --- (3) Executive summary: top findings ---
  const allFindings: Array<Finding & { moduleId: string; moduleName: string; moduleStatus: string }> = results.results.flatMap((r) =>
    r.findings.map((f) => ({
      ...f,
      moduleId: r.moduleId,
      moduleName: r.moduleName,
      moduleStatus: r.status
    }))
  );

  const severityRank: Record<SeverityLevel, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const topFindings = [...allFindings]
    .sort((a, b) => severityRank[b.severity] - severityRank[a.severity])
    .slice(0, 5);

  // --- (2) Filters / search ---
  const [query, setQuery] = useState('');
  const [minSeverity, setMinSeverity] = useState<SeverityLevel>('info');
  const [moduleFilter, setModuleFilter] = useState<string>('all');

  const filteredFindings = allFindings.filter((f) => {
    const text = `${f.title} ${f.description} ${f.evidence || ''} ${f.recommendation || ''} ${f.moduleName}`.toLowerCase();
    const okQuery = !query.trim() || text.includes(query.trim().toLowerCase());
    const okSeverity = severityRank[f.severity] >= severityRank[minSeverity];
    const okModule = moduleFilter === 'all' || f.moduleId === moduleFilter;
    return okQuery && okSeverity && okModule;
  });

  const uniqueModules = results.results.map(r => ({ id: r.moduleId, name: r.moduleName }));

  // --- (5) Export Bundle (ZIP) ---
  const handleExportBundle = async () => {
    if (!results) return;

    const zip = new JSZip();

    // JSON: on préfère l'artifact serveur si dispo (source of truth)
    if (results.artifacts?.json) {
      const resp = await fetchArtifact(results.artifacts.json);
      if (resp?.ok) {
        zip.file(`pentest-${results.scanId}.json`, await resp.text());
      }
    } else {
      zip.file(`pentest-${results.scanId}.json`, JSON.stringify(results, null, 2));
    }

    // PDF: on inclut le PDF serveur si dispo
    if (results.artifacts?.pdf) {
      const resp = await fetchArtifact(results.artifacts.pdf);
      if (resp?.ok) {
        const blob = await resp.blob();
        zip.file(`pentest-${results.scanId}.pdf`, blob);
      }
    }

    // Exploitation guide (md)
    if (results.artifacts?.exploitation_guide) {
      const resp = await fetchArtifact(results.artifacts.exploitation_guide);
      if (resp?.ok) {
        zip.file(`pentest-${results.scanId}_EXPLOITATION_GUIDE.md`, await resp.text());
      }
    }

    // Petit README
    zip.file(
      'README.txt',
      `Pentest Assistant bundle\n\nContenu:\n- JSON (résultats bruts)\n- PDF (si généré côté serveur)\n- EXPLOITATION_GUIDE.md (si généré)\n\nNote: certains artefacts peuvent être absents si le scan n'a pas demandé leur génération.\n`
    );

    const out = await zip.generateAsync({ type: 'blob' });
    const url = URL.createObjectURL(out);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pentest-${results.scanId}-bundle.zip`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="h-full bg-[#0d1117]">
      <div className="p-6 space-y-6">
        {/* En-tête */}
        <div className="flex items-start justify-between">
          <div>
            <h2 className="text-2xl font-bold text-[#c9d1d9] mb-2">
              Résultats de l'Analyse
            </h2>
            <p className="text-[#7d8590]">
              Cible: <span className="text-[#58a6ff] font-mono">{results.target.hostname}</span>
            </p>
            <p className="text-[#7d8590] text-sm">
              {results.timestamp.toLocaleString()} • Durée: {(results.totalDuration / 1000).toFixed(2)}s
            </p>
          </div>
          <div className="flex gap-2 flex-wrap justify-end">
            <button
              onClick={handleOpenExploitGuide}
              disabled={!results.artifacts?.exploitation_guide}
              className="px-4 py-2 bg-[#6e40c9] hover:bg-[#8250df] text-white rounded-md text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              title={!results.artifacts?.exploitation_guide ? 'Guide non disponible (relancez un scan)' : 'Télécharger le guide'}
            >
              Exploitation Guide
            </button>
            <button
              onClick={onExportJSON}
              className="px-4 py-2 bg-[#238636] hover:bg-[#2ea043] text-white rounded-md text-sm transition-colors"
            >
              Export JSON
            </button>
            <button
              onClick={onExportPDF}
              disabled={!results.artifacts?.pdf}
              className="px-4 py-2 bg-[#1f6feb] hover:bg-[#388bfd] text-white rounded-md text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              title={!results.artifacts?.pdf ? 'PDF disponible uniquement via la commande "scan" (full scan) — pas via "scanmod".' : 'Télécharger le PDF'}
            >
              Export PDF
            </button>
            <button
              onClick={handleExportBundle}
              className="px-4 py-2 bg-[#2dba4e] hover:bg-[#2ea043] text-white rounded-md text-sm transition-colors"
              title="Télécharger un ZIP (JSON + PDF + Exploitation Guide)"
            >
              Export Bundle
            </button>
          </div>
        </div>
        
        {/* Score de risque */}
        <div className={`p-6 rounded-lg border ${getSeverityBgColor(results.overallSeverity)}`}>
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-[#c9d1d9] mb-1">
                Score de Risque Global
              </h3>
              <p className="text-[#7d8590] text-sm">
                Basé sur {results.summary.totalFindings} constats détectés
              </p>
            </div>
            <div className="text-right">
              <div className={`text-5xl font-bold ${getRiskScoreColor(results.riskScore)}`}>
                {results.riskScore}
              </div>
              <div className="text-sm text-[#7d8590]">/ 100</div>
              <div className={`text-sm font-semibold uppercase mt-1 ${getSeverityColor(results.overallSeverity)}`}>
                {results.overallSeverity}
              </div>
            </div>
          </div>
        </div>
        
        {/* Statistiques */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-lg bg-[#161b22] border border-[#30363d]">
            <div className="text-[#7d8590] text-sm mb-1">Modules</div>
            <div className="text-2xl font-bold text-[#c9d1d9]">
              {results.summary.completedModules}/{results.summary.totalModules}
            </div>
          </div>
          <div className="p-4 rounded-lg bg-[#161b22] border border-[#30363d]">
            <div className="text-[#7d8590] text-sm mb-1">Critique</div>
            <div className="text-2xl font-bold text-[#ff5f56]">
              {results.summary.findingsBySeverity.critical}
            </div>
          </div>
          <div className="p-4 rounded-lg bg-[#161b22] border border-[#30363d]">
            <div className="text-[#7d8590] text-sm mb-1">Haute</div>
            <div className="text-2xl font-bold text-[#ff9500]">
              {results.summary.findingsBySeverity.high}
            </div>
          </div>
          <div className="p-4 rounded-lg bg-[#161b22] border border-[#30363d]">
            <div className="text-[#7d8590] text-sm mb-1">Moyenne</div>
            <div className="text-2xl font-bold text-[#ffd60a]">
              {results.summary.findingsBySeverity.medium}
            </div>
          </div>
        </div>
        
        {/* Bloc erreurs techniques (séparé des vulnérabilités) */}
        {technicalIssues.length > 0 && (
          <div className="rounded-lg border border-[#303d3d] bg-[#161b22] p-4">
            <h3 className="text-lg font-semibold text-[#c9d1d9] mb-2">Incidents techniques</h3>
            <p className="text-sm text-[#7d8590] mb-3">
              Ces modules ont rencontré une erreur technique ou un timeout. Ils <b>n’impactent pas</b> le score global et n’ajoutent pas de constats.
            </p>
            <div className="space-y-2">
              {technicalIssues.map((r) => (
                <div key={r.moduleId} className="flex items-start justify-between gap-3 border border-[#303d3d] rounded-md p-3 bg-[#0d1117]">
                  <div>
                    <div className="text-[#c9d1d9] font-semibold">{r.moduleName}</div>
                    <div className="text-xs text-[#7d8590] font-mono break-all">{r.moduleId}</div>
                    {r.error && (
                      <div className="text-sm text-[#f85149] mt-2">{r.error}</div>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    {isTimeout(r) ? (
                      <span className="px-2 py-1 text-xs rounded bg-[#ff9500]/10 text-[#ff9500] border border-[#ff9500]/30">⏱️ Timeout</span>
                    ) : (
                      <span className="px-2 py-1 text-xs rounded bg-[#f85149]/10 text-[#f85149] border border-[#f85149]/30">⚠️ Technical Error</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Résultats par module */}
        <div className="space-y-4">
          <h3 className="text-xl font-semibold text-[#c9d1d9]">Détails par Module</h3>
          
          {results.results.map((result) => (
            <div
              key={result.moduleId}
              className="rounded-lg bg-[#161b22] border border-[#303d3d] overflow-hidden"
            >
              <div className="p-4 border-b border-[#303d3d] flex items-center justify-between">
                <div className="flex items-center gap-3">
                  {result.status === 'completed' && (
                    <CheckCircle className="w-5 h-5 text-[#3fb950]" />
                  )}
                  {result.status === 'failed' && (
                    <XCircle className="w-5 h-5 text-[#f85149]" />
                  )}
                  {result.status === 'timeout' && (
                    <AlertTriangle className="w-5 h-5 text-[#ff9500]" />
                  )}
                  <div>
                    <h4 className="font-semibold text-[#c9d1d9]">{result.moduleName}</h4>
                    <p className="text-sm text-[#7d8590]">
                      {result.findings.length} constat{result.findings.length !== 1 ? 's' : ''}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-sm font-semibold uppercase ${getSeverityColor(result.severity)}`}>
                    {result.severity}
                  </span>
                  <span className="text-xs text-[#7d8590]">
                    {result.duration ? `${result.duration}ms` : ''}
                  </span>
                </div>
              </div>
              
              {result.findings.length > 0 && (
                <div className="p-4 space-y-3">
                  {result.findings.map((finding) => (
                    <div
                      key={finding.id}
                      className={`p-3 rounded-md border ${getSeverityBgColor(finding.severity)}`}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <h5 className="font-semibold text-[#c9d1d9]">{finding.title}</h5>
                        <span className={`text-xs font-semibold uppercase ${getSeverityColor(finding.severity)}`}>
                          {finding.severity}
                        </span>
                      </div>
                      <p className="text-sm text-[#7d8590] mb-2">{finding.description}</p>
                      
                      {finding.evidence && (
                        <div className="mb-2">
                          <div className="text-xs text-[#7d8590] mb-1">Preuve:</div>
                          <code className="block text-xs bg-[#0d1117] p-2 rounded text-[#c9d1d9] font-mono">
                            {finding.evidence}
                          </code>
                        </div>
                      )}
                      
                      {finding.recommendation && (
                        <div className="flex gap-2 items-start text-sm">
                          <Info className="w-4 h-4 text-[#58a6ff] mt-0.5 flex-shrink-0" />
                          <span className="text-[#7d8590]">{finding.recommendation}</span>
                        </div>
                      )}
                      
                      {(finding.cwe || finding.owasp) && (
                        <div className="flex gap-3 mt-2 text-xs text-[#7d8590]">
                          {finding.cwe && <span>{finding.cwe}</span>}
                          {finding.owasp && <span>{finding.owasp}</span>}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
              
              {result.error && (
                <div className="p-4 text-sm text-[#f85149]">
                  Erreur: {result.error}
                </div>
              )}
            </div>
          ))}
        </div>

        {/* (3) Executive Summary */}
        <div className="rounded-lg border border-[#303d3d] bg-[#161b22] p-4">
          <h3 className="text-lg font-semibold text-[#c9d1d9] mb-2">Executive Summary</h3>
          <div className="text-sm text-[#7d8590]">Top 5 constats triés par sévérité (tous modules confondus)</div>
          <div className="mt-3 space-y-2">
            {topFindings.length === 0 ? (
              <div className="text-sm text-[#7d8590]">Aucun constat.</div>
            ) : (
              topFindings.map((f) => (
                <div key={f.id} className="flex items-start justify-between gap-3 border border-[#303d3d] rounded-md p-3 bg-[#0d1117]">
                  <div>
                    <div className="text-[#c9d1d9] font-semibold">{f.title}</div>
                    <div className="text-xs text-[#7d8590]">{f.moduleName}</div>
                  </div>
                  <div className={`text-xs font-semibold uppercase ${getSeverityColor(f.severity)}`}>{f.severity}</div>
                </div>
              ))
            )}
          </div>
        </div>

        {/* (2) Recherche + filtres */}
        <div className="rounded-lg border border-[#303d3d] bg-[#161b22] p-4">
          <h3 className="text-lg font-semibold text-[#c9d1d9] mb-3">Recherche & Filtres</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#303d3d] text-[#c9d1d9] text-sm"
              placeholder="Rechercher (titre, evidence, recommandation, module...)"
            />
            <select
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value as SeverityLevel)}
              className="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#303d3d] text-[#c9d1d9] text-sm"
            >
              <option value="info">INFO+</option>
              <option value="low">LOW+</option>
              <option value="medium">MEDIUM+</option>
              <option value="high">HIGH+</option>
              <option value="critical">CRITICAL</option>
            </select>
            <select
              value={moduleFilter}
              onChange={(e) => setModuleFilter(e.target.value)}
              className="w-full px-3 py-2 rounded bg-[#0d1117] border border-[#303d3d] text-[#c9d1d9] text-sm"
            >
              <option value="all">Tous les modules</option>
              {uniqueModules.map((m) => (
                <option key={m.id} value={m.id}>{m.name}</option>
              ))}
            </select>
          </div>
          <div className="mt-3 text-sm text-[#7d8590]">
            Résultats filtrés: <b>{filteredFindings.length}</b> / {allFindings.length}
          </div>
        </div>

        {/* (2) Vue findings globale filtrée */}
        <div className="space-y-3">
          <h3 className="text-xl font-semibold text-[#c9d1d9]">Findings (Global)</h3>
          {filteredFindings.length === 0 ? (
            <div className="text-sm text-[#7d8590]">Aucun finding ne correspond aux filtres.</div>
          ) : (
            filteredFindings.slice(0, 200).map((f) => (
              <div key={`${f.moduleId}:${f.id}`} className={`p-3 rounded-md border ${getSeverityBgColor(f.severity)}`}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="font-semibold text-[#c9d1d9]">{f.title}</div>
                    <div className="text-xs text-[#7d8590]">{f.moduleName}</div>
                  </div>
                  <div className={`text-xs font-semibold uppercase ${getSeverityColor(f.severity)}`}>{f.severity}</div>
                </div>
                {f.description && <p className="text-sm text-[#7d8590] mt-2">{f.description}</p>}
                {f.evidence && (
                  <div className="mt-2">
                    <div className="text-xs text-[#7d8590] mb-1">Preuve:</div>
                    <code className="block text-xs bg-[#0d1117] p-2 rounded text-[#c9d1d9] font-mono break-words whitespace-pre-wrap">{f.evidence}</code>
                  </div>
                )}
                {f.recommendation && (
                  <div className="mt-2 text-sm text-[#7d8590]">
                    <b>Recommandation:</b> {f.recommendation}
                  </div>
                )}
              </div>
            ))
          )}
          {filteredFindings.length > 200 && (
            <div className="text-xs text-[#7d8590]">Affichage limité à 200 results (pour performance). Affine les filtres.</div>
          )}
        </div>
      </div>
    </div>
  );
}
