import type { AuditEvent } from '../types';

export type HealthState = 'healthy' | 'warning' | 'error' | 'unavailable' | 'loading';
export type RiskLevel = 'low' | 'medium' | 'high';
export type StatusVariant = 'success' | 'warning' | 'error' | 'info' | 'pending' | 'neutral';

export function healthStateFrom(value: unknown): HealthState {
  if (value === true) return 'healthy';
  if (value === false) return 'error';
  if (typeof value !== 'string' || value.length === 0) return 'unavailable';
  const normalized = value.toLowerCase();
  if (['ok', 'healthy', 'connected', 'ready', 'available', 'loaded', 'up'].includes(normalized)) return 'healthy';
  if (['warning', 'degraded', 'partial'].includes(normalized)) return 'warning';
  if (['error', 'failed', 'down', 'disconnected', 'unhealthy', 'not_ready'].includes(normalized)) return 'error';
  return 'unavailable';
}

export function riskFromOperation(operation?: string): RiskLevel {
  const value = (operation || '').toLowerCase();
  if (value.includes('delete') || value.includes('execute') || value.includes('network')) return 'high';
  if (value.includes('write') || value.includes('move') || value.includes('create')) return 'medium';
  return 'low';
}

export function statusVariantForEvent(event: AuditEvent): StatusVariant {
  const value = `${event.decision || ''} ${event.category || ''}`.toLowerCase();
  if (value.includes('deny') || value.includes('fail') || value.includes('reject') || value.includes('warning')) return 'error';
  if (value.includes('approval') || value.includes('expired')) return 'warning';
  if (value.includes('allow') || value.includes('success') || value.includes('loaded') || value.includes('valid')) return 'success';
  return 'info';
}

export function formatEventCategory(category: string): string {
  return category
    .replace(/([a-z])([A-Z])/g, '$1 $2')
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export function shortFingerprint(hash?: string): string {
  if (!hash) return 'Not recorded';
  if (hash.length <= 18) return hash;
  return `${hash.slice(0, 8)}…${hash.slice(-8)}`;
}
