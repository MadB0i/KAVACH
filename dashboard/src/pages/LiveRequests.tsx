import { useEffect, useState, useCallback, useRef } from 'react';
import { getAuditEvents } from '../api';
import type { AuditEvent } from '../types';
import LoadingState from '../components/LoadingState';
import EmptyState from '../components/EmptyState';
import StatusBadge from '../components/StatusBadge';

export default function LiveRequests() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [paused, setPaused] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const maxEvents = 100;

  const fetchLatest = useCallback(async () => {
    try {
      const data = await getAuditEvents({ limit: 20 });
      if (data.length > 0) {
        setEvents((prev) => {
          const existingIds = new Set(prev.map((e) => `${e.sequence}-${e.timestamp}`));
          const newEvents = data.filter((e) => !existingIds.has(`${e.sequence}-${e.timestamp}`));
          const combined = [...newEvents, ...prev].slice(0, maxEvents);
          return combined;
        });
      }
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch events');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchLatest();
    const interval = setInterval(() => {
      if (!paused) fetchLatest();
    }, 3000);
    return () => clearInterval(interval);
  }, [fetchLatest, paused]);

  useEffect(() => {
    if (containerRef.current && !paused) {
      containerRef.current.scrollTop = 0;
    }
  }, [events, paused]);

  const getVariant = (ev: AuditEvent): 'success' | 'error' | 'warning' | 'info' => {
    const key = (ev.decision || ev.category || '').toLowerCase();
    if (key === 'allow' || key === 'allowed') return 'success';
    if (key === 'deny' || key === 'denied') return 'error';
    if (key === 'approval' || key === 'approve') return 'warning';
    return 'info';
  };

  const clearEvents = () => {
    setEvents([]);
    setLoading(false);
  };

  if (loading && events.length === 0) return <LoadingState message="Waiting for requests..." />;

  return (
    <div className="page">
      <div className="page__header">
        <h2 className="page__title">Live Requests</h2>
        <div className="page__actions">
          <button
            className={`btn btn--sm ${paused ? 'btn--primary' : 'btn--ghost'}`}
            onClick={() => setPaused(!paused)}
            aria-label={paused ? 'Resume live updates' : 'Pause live updates'}
          >
            {paused ? '\u25B6 Resume' : '\u23F8 Pause'}
          </button>
          <button className="btn btn--ghost btn--sm" onClick={clearEvents} aria-label="Clear events">
            Clear
          </button>
        </div>
      </div>

      {error && <div className="toast toast--error" role="alert">{error}</div>}
      {!paused && <p className="live-indicator"><span className="live-dot" aria-hidden="true" /> Live</p>}

      {events.length === 0 ? (
        <EmptyState icon={'\u25B6'} title="No Requests" description="Waiting for incoming requests..." />
      ) : (
        <div className="live-requests" ref={containerRef} role="log" aria-label="Live request events" aria-live="polite">
          {events.map((ev) => (
            <div key={`${ev.sequence}-${ev.timestamp}`} className="live-request-item">
              <span className="live-request-item__time">
                {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : '?'}
              </span>
              <code className="live-request-item__id" title={ev.request_id}>
                {ev.request_id?.slice(0, 16) || '-'}
              </code>
              <span className="live-request-item__op">{ev.operation || '-'}</span>
              <StatusBadge variant={getVariant(ev)} label={ev.decision || ev.category || '?'} />
              <span className="live-request-item__summary" title={ev.summary}>
                {ev.summary ? (ev.summary.length > 50 ? ev.summary.slice(0, 47) + '...' : ev.summary) : ''}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
