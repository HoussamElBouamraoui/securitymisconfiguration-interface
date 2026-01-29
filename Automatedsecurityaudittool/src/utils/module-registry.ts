import type { ModuleRegistry, ScanModule } from '@/types/scan';

/**
 * Registre central des modules de scan
 * Agit comme une table de routage entre noms logiques et implémentations
 */
class ModuleRegistryManager {
  private modules: ModuleRegistry = {};
  
  register(module: ScanModule): void {
    this.modules[module.id] = module;
  }
  
  unregister(moduleId: string): void {
    delete this.modules[moduleId];
  }
  
  get(moduleId: string): ScanModule | undefined {
    return this.modules[moduleId];
  }
  
  getAll(): ScanModule[] {
    return Object.values(this.modules);
  }
  
  getAllByCategory(category: 'network' | 'web'): ScanModule[] {
    return this.getAll().filter(m => m.category === category);
  }
  
  clear(): void {
    this.modules = {};
  }
}

export const moduleRegistry = new ModuleRegistryManager();
