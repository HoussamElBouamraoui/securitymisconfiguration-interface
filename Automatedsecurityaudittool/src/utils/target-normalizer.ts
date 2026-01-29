import type { NormalizedTarget, TargetType } from '@/types/scan';

/**
 * Normalise une cible (URL, hostname, IP) en une structure cohérente
 */
export function normalizeTarget(raw: string): NormalizedTarget {
  const trimmed = raw.trim();
  
  // Cas 1: URL complète
  const urlPattern = /^https?:\/\//i;
  if (urlPattern.test(trimmed)) {
    try {
      const url = new URL(trimmed);
      return {
        raw: trimmed,
        type: 'url',
        protocol: url.protocol.replace(':', ''),
        hostname: url.hostname,
        port: url.port ? parseInt(url.port) : (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname
      };
    } catch (e) {
      throw new Error('URL invalide');
    }
  }
  
  // Cas 2: IP address
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/;
  if (ipPattern.test(trimmed)) {
    const [ip, port] = trimmed.split(':');
    return {
      raw: trimmed,
      type: 'ip',
      hostname: ip,
      port: port ? parseInt(port) : undefined
    };
  }
  
  // Cas 3: Hostname (avec ou sans port)
  const hostnamePattern = /^([a-zA-Z0-9.-]+)(:\d+)?$/;
  const match = trimmed.match(hostnamePattern);
  if (match) {
    const [, hostname, portStr] = match;
    return {
      raw: trimmed,
      type: 'hostname',
      hostname: hostname,
      port: portStr ? parseInt(portStr.replace(':', '')) : undefined
    };
  }
  
  throw new Error('Format de cible non reconnu. Utilisez une URL, un nom d\'hôte ou une adresse IP.');
}

export function getTargetUrl(target: NormalizedTarget): string {
  const protocol = target.protocol || 'https';
  const port = target.port && target.port !== 80 && target.port !== 443 
    ? `:${target.port}` 
    : '';
  return `${protocol}://${target.hostname}${port}${target.path || ''}`;
}
