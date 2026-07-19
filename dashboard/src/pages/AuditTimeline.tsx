import { useEffect, useState, useCallback, useRef } from 'react';
import { useSearchParams } from 'react-router-dom';
import { getAuditEvents } from '../api';
import type { AuditEvent } from '../types';
import PageHeader from '../components/PageHeader';
import EmptyState from '../components/EmptyState';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import StatusBadge from '../components/StatusBadge';
import DetailDrawer from '../components/DetailDrawer';

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
  decisionallow: 'success',
  decisiondeny: 'error',
  approvalrequested: 'warning',
  approvalapproved: 'success',
  approvaldenied: 'error',
  executionfailed: 'error',
  executionsucceeded: 'success',
};

export default function AuditTimeline() {
  const [searchParams] = useSearchParams();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const eventsRef = useRef(events);
  eventsRef.current = events;
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState('');
  const [requestIdFilter, setRequestIdFilter] = useState(() => searchParams.get('request') || '');
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const fetchEvents = useCallback(async (append = false) => {
    if (!append) setLoading(true);
    else setLoadingMore(true);
    try {
      const before = append && eventsRef.current.length > 0
        ? Math.min(...eventsRef.current.map((event) => event.sequence))
        : undefined;
      const data = await getAuditEvents({
        before,
        limit: PAGE_SIZE,
        category: categoryFilter || undefined,
        request_id: requestIdFilter || undefined,
      });
      if (append) {
        setEvents((prev) => {
          const existing = new Set(prev.map((event) => event.sequence));
          return [...prev, ...data.filter((event) => !existing.has(event.sequence))];
        });
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
  }, [categoryFilter, requestIdFilter]);

  useEffect(() => {
    fetchEvents();
    const interval = setInterval(() => fetchEvents(), 10000);
    return () => clearInterval(interval);
  }, [fetchEvents]);

  const getVariant = (ev: AuditEvent): 'success' | 'error' | 'warning' | 'info' => {
    const key = (ev.decision || ev.category || '').toLowerCase();
    return categoryVariant[key] || 'info';
  };

  if (loading) return <LoadingState message="Loading audit events..." />;
  if (error) return <ErrorState title="Failed to load audit events" message={error} onRetry={() => fetchEvents()} />;

  return (
    <div className="page">
      <PageHeader
        title="Audit Timeline"
        subtitle={`${events.length} event${events.length !== 1 ? 's' : ''}`}
      />

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
            <option value="DecisionAllow">Allowed</option>
            <option value="DecisionDeny">Denied</option>
            <option value="ApprovalRequested">Approval requested</option>
            <option value="ApprovalApproved">Approval approved</option>
            <option value="ApprovalDenied">Approval denied</option>
            <option value="ApprovalExpired">Approval expired</option>
            <option value="ApprovalConsumed">Approval consumed</option>
            <option value="ExecutionStarted">Execution started</option>
            <option value="ExecutionSucceeded">Execution succeeded</option>
            <option value="ExecutionFailed">Execution failed</option>
            <option value="SecurityWarning">Security warning</option>
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
            <button
              key={`${ev.sequence}-${ev.timestamp}`}
              className="timeline__item timeline__item--button"
              role="listitem"
              onClick={() => setSelectedEvent(ev)}
              aria-label={`Open audit event ${ev.sequence}`}
            >
              <div className="timeline__marker" aria-hidden="true">
                <span className={`timeline__dot timeline__dot--${getVariant(ev)}`} />
              </div>
              <div className="timeline__content">
                <div className="timeline__header">
                  <span className="timeline__seq">#{ev.sequence}</span>
                  <span className="timeline__time">
                    {ev.timestamp ? new Date(ev.timestamp).toLocaleString() : '?'}
                  </span>
                  <StatusBadge variant={getVariant(ev)} label={ev.decision || ev.category || 'event'} />
                </div>
                <div className="timeline__details">
                  <span><strong>Request:</strong> <code>{ev.request_id || '\u2014'}</code></span>
                  <span><strong>Operation:</strong> {ev.operation || '\u2014'}</span>
                  {ev.agent_id && <span><strong>Agent:</strong> {ev.agent_id}</span>}
                </div>
                {ev.summary && <p className="timeline__summary">{ev.summary}</p>}
              </div>
            </button>
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

      <DetailDrawer
        open={selectedEvent !== null}
        title={selectedEvent ? `Audit event #${selectedEvent.sequence}` : 'Audit event'}
        onClose={() => setSelectedEvent(null)}
      >
        {selectedEvent && (
          <dl className="detail-list">
            <div><dt>Category</dt><dd>{selectedEvent.category}</dd></div>
            <div><dt>Decision</dt><dd>{selectedEvent.decision || '\u2014'}</dd></div>
            <div><dt>Request ID</dt><dd><code>{selectedEvent.request_id || '\u2014'}</code></dd></div>
            <div><dt>Agent</dt><dd>{selectedEvent.agent_id || '\u2014'}</dd></div>
            <div><dt>Operation</dt><dd>{selectedEvent.operation || '\u2014'}</dd></div>
            <div><dt>Resource</dt><dd>{selectedEvent.resource_kind || '\u2014'}</dd></div>
            <div><dt>Reason</dt><dd>{selectedEvent.reason_code || '\u2014'}</dd></div>
            <div><dt>Matched rules</dt><dd>{selectedEvent.matched_rule_ids?.join(', ') || '\u2014'}</dd></div>
            <div><dt>Current hash</dt><dd><code>{selectedEvent.current_hash || '\u2014'}</code></dd></div>
            <div><dt>Previous hash</dt><dd><code>{selectedEvent.previous_hash || '\u2014'}</code></dd></div>
          </dl>
        )}
      </DetailDrawer>
    </div>
  );
}
