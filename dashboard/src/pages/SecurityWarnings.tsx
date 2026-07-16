import { useEffect, useState, useCallback } from 'react';
import { getAuditEvents } from '../api';
import type { AuditEvent } from '../types';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import EmptyState from '../components/EmptyState';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';

export default function SecurityWarnings() {
  const [warnings, setWarnings] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchWarnings = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getAuditEvents({ category: 'SecurityWarning', limit: 100 });
      setWarnings(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load security warnings');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchWarnings();
    const interval = setInterval(fetchWarnings, 15000);
    return () => clearInterval(interval);
  }, [fetchWarnings]);

  if (loading) return <LoadingState message="Loading security warnings..." />;
  if (error) return <ErrorState title="Failed to load warnings" message={error} onRetry={fetchWarnings} />;

  return (
    <div className="page">
      <PageHeader title="Security Warnings" subtitle={`${warnings.length} warning${warnings.length !== 1 ? 's' : ''}`} />

      {warnings.length === 0 ? (
        <EmptyState icon={'\u2713'} title="No Security Warnings" description="All clear. No security warnings recorded." />
      ) : (
        <div className="warning-list">
          {warnings.map((w) => (
            <div key={`${w.sequence}-${w.timestamp}`} className="warning-card">
              <div className="warning-card__header">
                <StatusBadge variant="error" label="Security Warning" />
                <span className="warning-card__time">
                  {w.timestamp ? new Date(w.timestamp).toLocaleString() : '?'}
                </span>
              </div>
              <div className="warning-card__body">
                <p><strong>Request</strong> <code>{w.request_id || '\u2014'}</code></p>
                {w.operation && <p><strong>Operation</strong> {w.operation}</p>}
                {w.summary && <p><strong>Details</strong> {w.summary}</p>}
                {w.agent_id && <p><strong>Agent</strong> {w.agent_id}</p>}
              </div>
              {w.details && Object.keys(w.details).length > 0 && (
                <pre className="warning-card__details">{JSON.stringify(w.details, null, 2)}</pre>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
