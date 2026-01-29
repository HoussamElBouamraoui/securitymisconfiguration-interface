// Types fondamentaux pour le système de scan

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ConfidenceLevel = 'certain' | 'firm' | 'tentative';
export type ScanStatus = 'pending' | 'running' | 'started' | 'completed' | 'failed' | 'timeout';
export type TargetType = 'url' | 'hostname' | 'ip';

export interface NormalizedTarget {
  raw: string;
  type: TargetType;
  protocol?: string;
  hostname: string;
  port?: number;
  path?: string;
}

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  evidence?: string;
  recommendation?: string;
  cwe?: string;
  owasp?: string;
}

export interface ScanResult {
  moduleId: string;
  moduleName: string;
  status: ScanStatus;
  startTime: Date;
  endTime?: Date;
  duration?: number;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  findings: Finding[];
  metadata?: Record<string, unknown>;
  error?: string;
}

export interface AggregatedResults {
  target: NormalizedTarget;
  scanId: string;
  timestamp: Date;
  totalDuration: number;
  overallSeverity: SeverityLevel;
  riskScore: number;
  summary: {
    totalModules: number;
    completedModules: number;
    failedModules: number;
    totalFindings: number;
    findingsBySeverity: Record<SeverityLevel, number>;
  };
  results: ScanResult[];
  metadata: {
    version: string;
    aggressiveness: 'passive' | 'normal' | 'aggressive';
    timeout: number;
  };
  artifacts?: {
    json?: string;
    pdf?: string;
    exploitation_guide?: string;
  };
}

export interface ScanModule {
  id: string;
  name: string;
  description: string;
  category: 'network' | 'web';
  execute: (target: NormalizedTarget) => Promise<ScanResult>;
}

export interface ModuleRegistry {
  [key: string]: ScanModule;
}
