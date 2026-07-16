import { useEffect, useState, useCallback } from 'react';
import { getAuditEvents } from '../api';
import type { AuditEvent } from '../types';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import EmptyState from '../components/EmptyState';
import StatusBadge from '../components/StatusBadge';

const PAGE_SIZE = 25;

const categoryVariant: Record<string, 'success' | 'error' | 'warning' | 'info'> = {
  allow: 'success',
  allowed: 'success',
  deny: 'error',
  denied: 'error',
  approval: 'warning',
  approve: 'warning',
  info: 'info',
  securitywarning: 'warning',
};

export default function AuditTimeline() {
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState('');
  const [requestIdFilter, setRequestIdFilter] = useState('');

  const fetchEvents = useCallback(async (append = false) => {
    if (!append) setLoading(true);
    else setLoadingMore(true);
    try {
      const after = append && events.length > 0 ? events[events.length - 1]!.sequence : undefined;
      const data = await getAuditEvents({
        after,
        limit: PAGE_SIZE,
        category: categoryFilter || undefined,
        request_id: requestIdFilter || undefined,
      });
      if (append) {
        setEvents((prev) => [...prev, ...data]);
      } else {
        setEvents(data);
      }
      setError(null);
    } catch (err) {
      if (!append) setError(err instanceof Error ? err.message : 'Failed to load events');
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  }, [categoryFilter, requestIdFilter, events]);

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(() => fetchEvents(), 10000);
    return () => clearInterval(interval);
  }, [categoryFilter, requestIdFilter]);

  const getVariant = (ev: AuditEvent): 'success' | 'error' | 'warning' | 'info' => {
    const key = (ev.decision || ev.category || '').toLowerCase();
    return categoryVariant[key] || 'info';
  };

  if (loading) return <LoadingState message="Loading audit events..." />;
  if (error) return <ErrorState title="Failed to load audit events" message={error} onRetry={() => fetchEvents()} />;

  return (
    <div className="page">
      <h2 className="page__title">Audit Timeline</h2>

      <div className="filter-bar">
        <div className="form-group">
          <label htmlFor="category-filter" className="form-label">Category</label>
          <select
            id="category-filter"
            className="form-select"
            value={categoryFilter}
            onChange={(e) => { setCategoryFilter(e.target.value); setEvents([]); }}
          >
            <option value="">All</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
            <option value="approval">Approval</option>
            <option value="info">Info</option>
            <option value="securitywarning">Security Warning</option>
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="request-id-filter" className="form-label">Request ID</label>
          <input
            id="request-id-filter"
            type="text"
            className="form-input"
            value={requestIdFilter}
            onChange={(e) => { setRequestIdFilter(e.target.value); setEvents([]); }}
            placeholder="Filter by request ID"
          />
        </div>
      </div>

      {events.length === 0 ? (
        <EmptyState icon={'\u29D6'} title="No Audit Events" description="No events match the current filters." />
      ) : (
        <div className="timeline" role="list">
          {events.map((ev) => (
            <div key={`${ev.sequence}-${ev.timestamp}`} className="timeline__item" role="listitem">
              <div className="timeline__marker" aria-hidden="true">
                <span className={`timeline__dot timeline__dot--${getVariant(ev)}`} />
              </div>
              <div className="timeline__content">
                <div className="timeline__header">
                  <span className="timeline__seq">#{ev.sequence}</span>
                  <span className="timeline__time">{ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '?'}</span>
                  <StatusBadge variant={getVariant(ev)} label={ev.decision || ev.category || 'event'} />
                </div>
                <div className="timeline__details">
                  <span><strong>Request:</strong> <code>{ev.request_id || '-'}</code></span>
                  <span><strong>Operation:</strong> {ev.operation || '-'}</span>
                  {ev.agent_id && <span><strong>Agent:</strong> {ev.agent_id}</span>}
                </div>
                {ev.summary && <p className="timeline__summary">{ev.summary}</p>}
              </div>
            </div>
          ))}
        </div>
      )}

      {events.length > 0 && (
        <div className="load-more">
          <button
            className="btn btn--ghost"
            onClick={() => fetchEvents(true)}
            disabled={loadingMore}
            aria-label="Load more events"
          >
            {loadingMore ? 'Loading...' : 'Load More'}
          </button>
        </div>
      )}
    </div>
  );
}
