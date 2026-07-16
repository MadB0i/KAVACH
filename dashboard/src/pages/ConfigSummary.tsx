import { useEffect, useState, useCallback } from 'react';
import { getStatus, getPolicies, getReady } from '../api';
import type { StatusInfo, PolicyInfo, ReadyStatus } from '../types';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

export default function ConfigSummary() {
  const [statusInfo, setStatusInfo] = useState<StatusInfo | null>(null);
  const [policies, setPolicies] = useState<PolicyInfo[]>([]);
  const [ready, setReady] = useState<ReadyStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [s, p, r] = await Promise.all([getStatus(), getPolicies(), getReady()]);
      setStatusInfo(s);
      setPolicies(p);
      setReady(r);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch configuration');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  if (loading) return <LoadingState message="Loading configuration..." />;
  if (error) return <ErrorState title="Failed to load configuration" message={error} onRetry={fetchAll} />;

  return (
    <div className="page">
      <h2 className="page__title">Configuration Summary</h2>

      <div className="section">
        <h3 className="section__title">Service Info</h3>
        <div className="config-block">
          <div className="config-row">
            <span className="config-row__key">Service</span>
            <span className="config-row__value">{statusInfo?.service || '?'}</span>
          </div>
          <div className="config-row">
            <span className="config-row__key">Version</span>
            <span className="config-row__value">{statusInfo?.version || '?'}</span>
          </div>
          <div className="config-row">
            <span className="config-row__key">Bind Address</span>
            <span className="config-row__value">{statusInfo?.bind_address || '?'}</span>
          </div>
          <div className="config-row">
            <span className="config-row__key">Uptime</span>
            <span className="config-row__value">
              {statusInfo?.uptime !== undefined ? `${Math.floor(statusInfo.uptime / 3600)}h ${Math.floor((statusInfo.uptime % 3600) / 60)}m` : '?'}
            </span>
          </div>
        </div>
      </div>

      <div className="section">
        <h3 className="section__title">Policies ({policies.length})</h3>
        <div className="config-block">
          {policies.map((p) => (
            <div key={p.id} className="config-row">
              <span className="config-row__key">{p.name || p.id}</span>
              <span className="config-row__value">{p.rule_count ?? '?'} rules, effect: {p.default_effect || '?'}</span>
            </div>
          ))}
          {policies.length === 0 && <p className="config-empty">No policies loaded</p>}
        </div>
      </div>

      {ready && ready.adapters && (
        <div className="section">
          <h3 className="section__title">Adapter Status</h3>
          <div className="config-block">
            {Object.entries(ready.adapters).map(([name, status]) => (
              <div key={name} className="config-row">
                <span className="config-row__key">{name}</span>
                <span className="config-row__value config-row__value--mono">{String(status)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="config-note">
        <p>Full configuration is managed server-side. This dashboard displays derived information from available API endpoints.</p>
      </div>
    </div>
  );
}
