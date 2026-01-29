import type { AggregatedResults, NormalizedTarget, SeverityLevel, ConfidenceLevel } from '../types/scan';

export type A02ScanRequest = {
  target: string;
  connectTimeout?: number;
  readTimeout?: number;
  retries?: number;
  workers?: number;
  perScanTimebox?: number;
  turbo?: boolean;
  generatePdf?: boolean;
  /** Optionnel: exécuter un sous-scan unique (ex: "port_scanner_aggressive"). */
  scan?: string;
};

// Le backend Python tourne en local. En dev Vite on passe par un proxy (/api).
const API_BASE = '/api';

export async function runA02Scan(payload: A02ScanRequest): Promise<unknown> {
  const r = await fetch(`${API_BASE}/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`API scan error (${r.status}): ${text || r.statusText}`);
  }

  return r.json();
}

export async function runA02SingleScan(payload: Omit<A02ScanRequest, 'turbo' | 'generatePdf'> & { scan: string }): Promise<unknown> {
  // Pour un sous-scan, on désactive volontairement turbo/PDF côté UI.
  return runA02Scan({ ...payload, turbo: false, generatePdf: false });
}

/**
 * Si tu veux réutiliser l'UI existante (ScanResults) qui attend AggregatedResults,
 * on fait un mapping best-effort depuis le JSON du runner Python.
 */
export function mapRunnerJsonToAggregatedResults(targetRaw: string, data: any): AggregatedResults {
  const now = new Date();

  const target: NormalizedTarget = {
    raw: targetRaw,
    type: 'hostname',
    hostname: targetRaw
  };

  const scans = Array.isArray(data?.results)
    ? data.results
    : (Array.isArray(data) ? data : []);

  const toSeverity = (s: any): SeverityLevel => {
    const v = String(s || 'info').toLowerCase();
    if (v === 'critical' || v === 'high' || v === 'medium' || v === 'low' || v === 'info') return v;
    return 'info';
  };

  // Confidence: runner = low/medium/high
  const toConfidence = (c: any): ConfidenceLevel => {
    const v = String(c || 'low').toLowerCase();
    if (v === 'high') return 'certain';
    if (v === 'medium') return 'firm';
    return 'tentative';
  };

  // Statut module: runner = COMPLETED/PARTIAL/ERROR
  const toStatus = (s: any): 'completed' | 'failed' | 'timeout' => {
    const v = String(s || '').toUpperCase();
    if (v === 'ERROR' || v === 'FAILED') return 'failed';
    if (v === 'PARTIAL') {
      const err = String(s?.metadata?.error || '').toLowerCase();
      return err.includes('timeout') || err.includes('timebox') ? 'timeout' : 'timeout';
    }
    return 'completed';
  };

  // Ne compter que les findings valides (modules COMPLETED uniquement)
  const validScans = scans.filter((s: any) => String(s?.status || '').toUpperCase() === 'COMPLETED');

  const findings = validScans.flatMap((s: any) =>
    (Array.isArray(s?.findings) ? s.findings : []).map((f: any, idx: number) => ({
      id: `${s.scan_type || s.scanType || 'scan'}:${idx}:${f.title || 'finding'}`,
      title: f.title || 'Finding',
      severity: toSeverity(f.severity),
      confidence: toConfidence(f.confidence),
      description: f.risk || '',
      evidence: f.evidence || '',
      recommendation: f.recommendation || ''
    }))
  );

  const findingsBySeverity: Record<SeverityLevel, number> = {
    critical: findings.filter((f: any) => f.severity === 'critical').length,
    high: findings.filter((f: any) => f.severity === 'high').length,
    medium: findings.filter((f: any) => f.severity === 'medium').length,
    low: findings.filter((f: any) => f.severity === 'low').length,
    info: findings.filter((f: any) => f.severity === 'info').length
  };

  const totalFindings = findings.length;
  const totalModules = scans.length;

  const completedModules = scans.filter((s: any) => String(s?.status || '').toUpperCase() === 'COMPLETED').length;
  const failedModules = totalModules - completedModules;

  const severityRank: Record<SeverityLevel, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const overallSeverity = findings.reduce((acc: SeverityLevel, f: any) => {
    const sev = toSeverity(f?.severity);
    return severityRank[sev] > severityRank[acc] ? sev : acc;
  }, 'info');

  // Calcul score 0-100 à partir des findings valides (et jamais 0 s'il y a du HIGH/MEDIUM)
  const pointsBySev: Record<SeverityLevel, number> = { critical: 10, high: 7, medium: 4, low: 2, info: 0 };
  const weightByConf: Record<ConfidenceLevel, number> = { certain: 1.0, firm: 0.75, tentative: 0.4 };
  const rawPoints = findings.reduce((sum: number, f: any) => {
    const sev = f.severity as SeverityLevel;
    const conf = f.confidence as ConfidenceLevel;
    return sum + (pointsBySev[sev] ?? 0) * (weightByConf[conf] ?? 0.4);
  }, 0);

  // Normalisation simple (cap à 100)
  let riskScore = Math.min(100, Math.round(rawPoints));
  if (riskScore === 0 && (findingsBySeverity.high > 0 || findingsBySeverity.medium > 0 || findingsBySeverity.critical > 0)) {
    riskScore = 5; // plancher pro: s'il y a du HIGH/MEDIUM/CRITICAL, le score ne doit pas être 0
  }

  return {
    scanId: data?.scan_id || data?.scanId || crypto.randomUUID(),
    target,
    timestamp: now,
    totalDuration: Number(data?.duration_seconds ? (data.duration_seconds * 1000) : 0),
    overallSeverity,
    riskScore,
    summary: {
      totalModules,
      completedModules,
      failedModules,
      totalFindings,
      findingsBySeverity
    },
    results: scans.map((s: any) => ({
      moduleId: s.scan_type || s.scanType || 'scan',
      moduleName: s.scan_type || s.scanType || 'scan',
      status: toStatus(s.status),
      startTime: now,
      endTime: now,
      duration: 0,
      severity: toSeverity(s.severity),
      confidence: toConfidence(s.confidence),
      findings: (Array.isArray(s.findings) ? s.findings : []).map((f: any, idx: number) => ({
        id: `${s.scan_type || 'scan'}:${idx}:${f.title || 'finding'}`,
        title: f.title || 'Finding',
        severity: toSeverity(f.severity),
        confidence: toConfidence(f.confidence),
        description: f.risk || '',
        evidence: f.evidence || '',
        recommendation: f.recommendation || ''
      })),
      metadata: s?.metadata,
      error: s?.metadata?.error
    })),
    metadata: {
      version: '1.0.0',
      aggressiveness: data?.turbo ? 'aggressive' : 'normal',
      timeout: 30000
    },
    artifacts: {
      json: data?.artifacts?.json,
      pdf: data?.artifacts?.pdf,
      exploitation_guide: data?.artifacts?.exploitation_guide
    }
  };
}

export async function getA02ScansList(): Promise<{ count: number; scans: string[] }> {
  const r = await fetch(`${API_BASE}/scans`, { method: 'GET' });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`API scans error (${r.status}): ${text || r.statusText}`);
  }
  return r.json();
}
