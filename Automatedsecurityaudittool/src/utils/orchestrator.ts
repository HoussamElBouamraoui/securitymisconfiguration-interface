import type { NormalizedTarget, ScanResult, ScanModule } from '@/types/scan';
import { moduleRegistry } from './module-registry';
import { normalizeScanResult } from './normalizer';

/**
 * Orchestrateur central qui coordonne l'exécution des modules de scan
 */
export class ScanOrchestrator {
  private timeout: number;
  private maxParallelScans: number;
  
  constructor(timeout: number = 30000, maxParallelScans: number = 5) {
    this.timeout = timeout;
    this.maxParallelScans = maxParallelScans;
  }
  
  /**
   * Lance tous les scans disponibles en parallèle avec gestion du timeout
   */
  async executeAllScans(
    target: NormalizedTarget,
    onProgress?: (moduleId: string, status: 'started' | 'completed' | 'failed') => void
  ): Promise<ScanResult[]> {
    const modules = moduleRegistry.getAll();
    
    if (modules.length === 0) {
      throw new Error('Aucun module de scan enregistré');
    }
    
    return this.executeBatch(modules, target, onProgress);
  }
  
  /**
   * Lance uniquement les scans d'une catégorie spécifique
   */
  async executeScansByCategory(
    target: NormalizedTarget,
    category: 'network' | 'web',
    onProgress?: (moduleId: string, status: 'started' | 'completed' | 'failed') => void
  ): Promise<ScanResult[]> {
    const modules = moduleRegistry.getAllByCategory(category);
    
    if (modules.length === 0) {
      throw new Error(`Aucun module de catégorie ${category} enregistré`);
    }
    
    return this.executeBatch(modules, target, onProgress);
  }
  
  /**
   * Lance un scan spécifique
   */
  async executeSingleScan(
    target: NormalizedTarget,
    moduleId: string,
    onProgress?: (moduleId: string, status: 'started' | 'completed' | 'failed') => void
  ): Promise<ScanResult> {
    const module = moduleRegistry.get(moduleId);
    
    if (!module) {
      throw new Error(`Module ${moduleId} non trouvé`);
    }
    
    return this.executeModule(module, target, onProgress);
  }
  
  /**
   * Exécute un batch de modules en parallèle avec limite de concurrence
   */
  private async executeBatch(
    modules: ScanModule[],
    target: NormalizedTarget,
    onProgress?: (moduleId: string, status: 'started' | 'completed' | 'failed') => void
  ): Promise<ScanResult[]> {
    const results: ScanResult[] = [];
    
    // Exécution par batch pour limiter la concurrence
    for (let i = 0; i < modules.length; i += this.maxParallelScans) {
      const batch = modules.slice(i, i + this.maxParallelScans);
      const batchResults = await Promise.all(
        batch.map(module => this.executeModule(module, target, onProgress))
      );
      results.push(...batchResults);
    }
    
    return results;
  }
  
  /**
   * Exécute un module unique avec gestion du timeout
   */
  private async executeModule(
    module: ScanModule,
    target: NormalizedTarget,
    onProgress?: (moduleId: string, status: 'started' | 'completed' | 'failed') => void
  ): Promise<ScanResult> {
    const startTime = new Date();
    
    if (onProgress) {
      onProgress(module.id, 'started');
    }
    
    try {
      // Exécution avec timeout
      const result = await this.executeWithTimeout(
        module.execute(target),
        this.timeout
      );
      
      // Normalisation du résultat
      const normalized = normalizeScanResult(result);
      
      if (onProgress) {
        onProgress(module.id, 'completed');
      }
      
      return normalized;
      
    } catch (error) {
      const endTime = new Date();
      
      if (onProgress) {
        onProgress(module.id, 'failed');
      }
      
      // Retourne un résultat d'erreur normalisé
      return {
        moduleId: module.id,
        moduleName: module.name,
        status: error instanceof TimeoutError ? 'timeout' : 'failed',
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        severity: 'info',
        confidence: 'tentative',
        findings: [],
        error: error instanceof Error ? error.message : 'Erreur inconnue'
      };
    }
  }
  
  /**
   * Exécute une promesse avec un timeout
   */
  private executeWithTimeout<T>(promise: Promise<T>, timeout: number): Promise<T> {
    return Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        setTimeout(() => reject(new TimeoutError('Scan timeout')), timeout);
      })
    ]);
  }
}

class TimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TimeoutError';
  }
}

/**
 * Instance par défaut de l'orchestrateur
 */
export const defaultOrchestrator = new ScanOrchestrator(30000, 5);
