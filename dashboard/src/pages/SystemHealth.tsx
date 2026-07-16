import { useEffect, useState, useCallback } from 'react';
import { getHealth, getReady, getStatus } from '../api';
import type { HealthStatus, ReadyStatus, StatusInfo } from '../types';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import StatusBadge from '../components/StatusBadge';

interface HealthCard {
  label: string;
  status: string | undefined;
}

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

  const healthCards: HealthCard[] = [
    { label: 'API Status', status: health?.status },
    { label: 'Database', status: health?.database },
    { label: 'Policy Engine', status: health?.policy_engine },
    { label: 'Audit Store', status: health?.audit_store },
    { label: 'Approval Store', status: health?.approval_store },
  ];

  if (loading) return <LoadingState message="Checking system health..." />;
  if (error) return <ErrorState title="Health check failed" message={error} onRetry={fetchAll} />;

  return (
    <div className="page">
      <h2 className="page__title">System Health</h2>

      {statusInfo && (
        <div className="health-info">
          <p><strong>Service:</strong> {statusInfo.service}</p>
          <p><strong>Version:</strong> {statusInfo.version || '?'}</p>
          <p><strong>Bind Address:</strong> {statusInfo.bind_address || '?'}</p>
          {statusInfo.uptime !== undefined && <p><strong>Uptime:</strong> {Math.floor(statusInfo.uptime / 3600)}h {Math.floor((statusInfo.uptime % 3600) / 60)}m</p>}
        </div>
      )}

      <div className="health-grid health-grid--large">
        {healthCards.map((card) => (
          <div key={card.label} className="health-card health-card--detailed">
            <h3 className="health-card__title">{card.label}</h3>
            <StatusBadge variant={getVariant(card.status)} label={card.status || 'Unknown'} />
          </div>
        ))}
      </div>

      {ready && (
        <div className="section">
          <h3 className="section__title">Readiness</h3>
          <div className="health-info">
            <p><strong>Ready:</strong> <StatusBadge variant={ready.ready ? 'success' : 'error'} label={ready.ready ? 'Yes' : 'No'} /></p>
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
        </div>
      )}
    </div>
  );
}
