import { useEffect, useState, useCallback } from 'react';
import { getStatus, getPolicies, getReady } from '../api';
import type { StatusInfo, PolicyInfo, ReadyStatus } from '../types';
import PageHeader from '../components/PageHeader';
import SectionCard from '../components/SectionCard';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import { Settings2 } from 'lucide-react';

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
      <PageHeader title="Configuration Summary" icon={Settings2} eyebrow="Runtime metadata" />

      <SectionCard title="Service Info">
        <div className="config-block">
          <div className="config-row">
            <span className="config-row__key">Service</span>
            <span className="config-row__value">{statusInfo?.service || 'Unavailable'}</span>
          </div>
          <div className="config-row">
            <span className="config-row__key">Version</span>
            <span className="config-row__value">{statusInfo?.version || 'Unavailable'}</span>
          </div>
          <div className="config-row">
            <span className="config-row__key">Bind Address</span>
            <span className="config-row__value">{statusInfo?.bind || statusInfo?.bind_address || 'Unavailable'}</span>
          </div>
          <div className="config-row">
            <span className="config-row__key">Uptime</span>
            <span className="config-row__value">
              {(statusInfo?.uptime_seconds ?? statusInfo?.uptime) !== undefined
                ? `${Math.floor((statusInfo?.uptime_seconds ?? statusInfo?.uptime ?? 0) / 3600)}h ${Math.floor(((statusInfo?.uptime_seconds ?? statusInfo?.uptime ?? 0) % 3600) / 60)}m`
                : 'Unavailable'}
            </span>
          </div>
        </div>
      </SectionCard>

      <SectionCard title={`Policies (${policies.length})`}>
        <div className="config-block">
          {policies.length === 0 ? (
            <div className="config-empty">No policies loaded</div>
          ) : (
            policies.map((p) => (
              <div key={p.policy_id || p.id} className="config-row">
                <span className="config-row__key">{p.policy_name || p.name || p.policy_id || p.id}</span>
                <span className="config-row__value">
                  {p.rule_count ?? 'Unavailable'} rules, effect: {p.default_effect || 'not exposed'}
                </span>
              </div>
            ))
          )}
        </div>
      </SectionCard>

      {ready && (
        <SectionCard title="Adapter Status">
          <div className="config-block">
            {Object.entries(ready.adapters || {
              filesystem: ready.adapter_filesystem,
              command: ready.adapter_command,
              network: ready.adapter_network,
            }).map(([name, status]) => (
              <div key={name} className="config-row">
                <span className="config-row__key">{name}</span>
                <span className="config-row__value">{status === undefined ? 'Unavailable' : String(status)}</span>
              </div>
            ))}
          </div>
        </SectionCard>
      )}

      <div className="config-note">
        Full configuration is managed server-side. This dashboard displays derived information from available API endpoints.
      </div>
    </div>
  );
}
