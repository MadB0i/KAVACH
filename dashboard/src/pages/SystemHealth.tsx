import { useEffect, useState, useCallback } from 'react';
import { getHealth, getReady, getStatus } from '../api';
import type { HealthStatus, ReadyStatus, StatusInfo } from '../types';
import PageHeader from '../components/PageHeader';
import SectionCard from '../components/SectionCard';
import StatusBadge from '../components/StatusBadge';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

export default function SystemHealth() {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [ready, setReady] = useState<ReadyStatus | null>(null);
  const [statusInfo, setStatusInfo] = useState<StatusInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    try {
      const [h, r, s] = await Promise.all([getHealth(), getReady(), getStatus()]);
      setHealth(h);
      setReady(r);
      setStatusInfo(s);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch health data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 15000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  const getVariant = (s?: string): 'success' | 'error' | 'info' => {
    if (!s) return 'info';
    const v = s.toLowerCase();
    if (v === 'ok' || v === 'healthy' || v === 'connected' || v === 'ready') return 'success';
    if (v === 'error' || v === 'disconnected' || v === 'down') return 'error';
    return 'info';
  };

  if (loading) return <LoadingState message="Checking system health..." />;
  if (error) return <ErrorState title="Health Check Failed" message={error} onRetry={fetchAll} />;

  return (
    <div className="page">
      <PageHeader
        title="System Health"
        subtitle={
          statusInfo
            ? `${statusInfo.service} v${statusInfo.version || '?'} \u2014 Bind: ${statusInfo.bind || '?'}`
            : undefined
        }
      />

      {statusInfo && statusInfo.uptime_seconds !== undefined && (
        <div className="health-info">
          <p><strong>Service</strong> {statusInfo.service}</p>
          <p><strong>Version</strong> {statusInfo.version || '?'}</p>
          <p><strong>Bind Address</strong> {statusInfo.bind || '?'}</p>
          <p>
            <strong>Uptime</strong>{' '}
            {Math.floor(statusInfo.uptime_seconds / 3600)}h {Math.floor((statusInfo.uptime_seconds % 3600) / 60)}m
          </p>
        </div>
      )}

      <SectionCard title="Component Status">
        <div className="health-grid health-grid--large">
          {[
            { label: 'API', status: health?.status },
            { label: 'Readiness', status: ready?.ready ? 'ready' : 'not ready' },
            { label: 'Policy Engine', status: ready ? `${ready.policy_count ?? 0} loaded` : undefined },
            { label: 'Audit Store', status: ready?.audit_store },
            { label: 'Approval Store', status: ready?.approval_store },
          ].map((c) => (
            <div key={c.label} className="health-card health-card--detailed">
              <h3 className="health-card__title">{c.label}</h3>
              <StatusBadge variant={getVariant(c.status)} label={c.status || '\u2014'} />
            </div>
          ))}
        </div>
      </SectionCard>

      {ready && (
        <SectionCard title="Readiness">
          <div className="health-info">
            <p><strong>Ready</strong>{' '}<StatusBadge variant={ready.ready ? 'success' : 'error'} label={ready.ready ? 'Yes' : 'No'} /></p>
          </div>
          {ready.adapters && Object.keys(ready.adapters).length > 0 && (
            <div className="health-grid">
              {Object.entries(ready.adapters).map(([name, status]) => (
                <div key={name} className="health-card">
                  <span className="health-card__label">{name}</span>
                  <StatusBadge variant={getVariant(status)} label={status} />
                </div>
              ))}
            </div>
          )}
        </SectionCard>
      )}
    </div>
  );
}
