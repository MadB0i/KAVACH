import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  ChevronDown,
  Copy,
  Filter,
  Fingerprint,
  ListFilter,
  RefreshCw,
  Search,
  ShieldCheck,
  TerminalSquare,
} from 'lucide-react';
import { useSearchParams } from 'react-router-dom';
import { getAuditEvents, verifyAudit } from '../api';
import type { AuditEvent, AuditVerifyResult } from '../types';
import DataTable from '../components/DataTable';
import DetailDrawer from '../components/DetailDrawer';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import EventTimeline from '../components/EventTimeline';
import LoadingSkeleton from '../components/LoadingSkeleton';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';
import { formatEventCategory, shortFingerprint, statusVariantForEvent } from '../utils/presentation';

const PAGE_STEP = 100;
const categories = [
  { value: '', label: 'All events' },
  { value: 'DecisionAllow', label: 'Allowed' },
  { value: 'DecisionDeny', label: 'Denied' },
  { value: 'ApprovalRequested', label: 'Approval' },
  { value: 'ExecutionFailed', label: 'Failed' },
  { value: 'SecurityWarning', label: 'Warnings' },
];

export default function AuditTimeline() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [verification, setVerification] = useState<AuditVerifyResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [category, setCategory] = useState(searchParams.get('category') || '');
  const [requestId, setRequestId] = useState(searchParams.get('request_id') || '');
  const [search, setSearch] = useState('');
  const [limit, setLimit] = useState(PAGE_STEP);
  const [view, setView] = useState<'table' | 'timeline'>('table');
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const fetchEvents = useCallback(async (manual = false) => {
    if (manual) setRefreshing(true);
    else setLoading(true);
    try {
      const [eventData, auditData] = await Promise.all([
        getAuditEvents({
          limit,
          category: category || undefined,
          request_id: requestId.trim() || undefined,
        }),
        verifyAudit(),
      ]);
      setEvents([...eventData].sort((a, b) => b.sequence - a.sequence));
      setVerification(auditData);
      setError(null);
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : 'Failed to load audit events');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [category, limit, requestId]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (category) params.set('category', category);
    if (requestId.trim()) params.set('request_id', requestId.trim());
    setSearchParams(params, { replace: true });
  }, [category, requestId, setSearchParams]);

  useEffect(() => {
    fetchEvents();
  }, [fetchEvents]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return events;
    return events.filter((event) => [
      event.category,
      event.request_id,
      event.agent_id,
      event.operation,
      event.resource_kind,
      event.reason_code,
      event.current_hash,
      event.event_id,
    ].some((value) => value?.toLowerCase().includes(query)));
  }, [events, search]);

  const copyFingerprint = async (value?: string) => {
    if (value) await navigator.clipboard.writeText(value);
  };

  if (error && events.length === 0) {
    return <ErrorState title="Audit timeline unavailable" message={error} onRetry={() => fetchEvents(true)} />;
  }

  return (
    <div className="page audit-page">
      <PageHeader
        eyebrow="Tamper-evident ledger"
        title="Audit Timeline"
        icon={TerminalSquare}
        subtitle="Correlate policy, approval, enforcement, and integrity events."
        actions={
          <div className="page-refresh">
            <StatusBadge
              variant={verification ? (verification.chain_valid ? 'success' : 'error') : 'neutral'}
              label={verification ? (verification.chain_valid ? 'Chain valid' : 'Chain invalid') : 'Integrity unavailable'}
            />
            <button className="btn btn--secondary btn--sm" type="button" onClick={() => fetchEvents(true)} disabled={refreshing}>
              <RefreshCw className={refreshing ? 'spin' : ''} size={14} />
              Refresh
            </button>
          </div>
        }
      />

      <section className="audit-toolbar" aria-label="Audit filters">
        <div className="audit-toolbar__search">
          <Search size={15} aria-hidden="true" />
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search loaded event fields…"
            aria-label="Search loaded audit events"
          />
        </div>
        <div className="audit-toolbar__request">
          <Filter size={14} aria-hidden="true" />
          <input
            type="text"
            value={requestId}
            onChange={(event) => setRequestId(event.target.value)}
            placeholder="Request correlation ID"
            aria-label="Filter by request ID"
          />
        </div>
        <div className="audit-toolbar__view" role="group" aria-label="Audit view">
          <button type="button" className={view === 'table' ? 'is-active' : ''} onClick={() => setView('table')}>Table</button>
          <button type="button" className={view === 'timeline' ? 'is-active' : ''} onClick={() => setView('timeline')}>Timeline</button>
        </div>
      </section>

      <div className="category-pills" aria-label="Event category filters">
        {categories.map((item) => (
          <button
            type="button"
            key={item.value || 'all'}
            className={category === item.value ? 'category-pill category-pill--active' : 'category-pill'}
            onClick={() => { setCategory(item.value); setLimit(PAGE_STEP); }}
            aria-pressed={category === item.value}
          >
            {item.label}
          </button>
        ))}
      </div>

      <div className="audit-summary-strip">
        <span><strong>{filtered.length}</strong> displayed</span>
        <span><strong>{verification?.event_count ?? 'Unavailable'}</strong> chain events</span>
        <span><strong>{verification?.verified_to ?? 'Unavailable'}</strong> verified sequence</span>
        <span><strong>{requestId.trim() || 'All requests'}</strong> correlation scope</span>
      </div>

      {loading ? (
        <div className="surface-panel"><LoadingSkeleton type="row" count={9} /></div>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={ListFilter}
          title={events.length === 0 ? 'No audit events recorded' : 'No events match these filters'}
          description={events.length === 0
            ? 'Evaluate a request through the KAVACH gateway to create the first tamper-evident security event.'
            : 'Clear the request correlation or category filter to widen the result set.'}
          action={events.length > 0 ? <button className="btn btn--secondary btn--sm" type="button" onClick={() => { setSearch(''); setRequestId(''); setCategory(''); }}>Clear filters</button> : undefined}
        />
      ) : view === 'timeline' ? (
        <div className="surface-panel surface-panel--flush">
          <EventTimeline events={filtered} onSelect={setSelected} />
        </div>
      ) : (
        <DataTable
          compact
          data={filtered}
          keyField={(event) => event.event_id || `${event.sequence}-${event.timestamp}`}
          rowLabel={(event) => `Audit event ${event.sequence}: ${formatEventCategory(event.category)}`}
          columns={[
            {
              key: 'sequence',
              header: 'Seq',
              className: 'cell-mono cell-sequence',
              render: (event) => <button className="table-link" type="button" onClick={() => setSelected(event)}>#{event.sequence}</button>,
            },
            {
              key: 'time',
              header: 'Timestamp',
              className: 'cell-mono',
              render: (event) => event.timestamp ? new Date(event.timestamp).toLocaleString() : <span className="unavailable-label">Unavailable</span>,
            },
            {
              key: 'event',
              header: 'Security event',
              render: (event) => (
                <button className="event-cell" type="button" onClick={() => setSelected(event)}>
                  <strong>{formatEventCategory(event.category)}</strong>
                  <span>{event.reason_code || event.operation || 'No additional classification'}</span>
                </button>
              ),
            },
            {
              key: 'severity',
              header: 'Outcome',
              render: (event) => <StatusBadge variant={statusVariantForEvent(event)} label={event.decision || formatEventCategory(event.category)} />,
            },
            {
              key: 'request',
              header: 'Request correlation',
              className: 'cell-mono cell-correlation',
              render: (event) => event.request_id || <span className="unavailable-label">Not correlated</span>,
            },
            {
              key: 'hash',
              header: 'Fingerprint',
              className: 'cell-mono',
              render: (event) => (
                <button className="fingerprint-button" type="button" onClick={() => copyFingerprint(event.current_hash)} disabled={!event.current_hash} title="Copy full fingerprint">
                  <Fingerprint size={12} />
                  {shortFingerprint(event.current_hash)}
                </button>
              ),
            },
          ]}
        />
      )}

      {events.length >= limit && (
        <div className="load-more">
          <button className="btn btn--secondary" type="button" onClick={() => setLimit((value) => value + PAGE_STEP)}>
            <ChevronDown size={15} />
            Load up to {limit + PAGE_STEP} events
          </button>
        </div>
      )}

      <DetailDrawer
        open={selected !== null}
        title={selected ? `Event #${selected.sequence}` : 'Audit event'}
        onClose={() => setSelected(null)}
      >
        {selected && (
          <div className="event-detail">
            <div className="event-detail__hero">
              <span className={`event-detail__icon event-detail__icon--${statusVariantForEvent(selected)}`}><Activity size={19} /></span>
              <div>
                <span>Security event</span>
                <h3>{formatEventCategory(selected.category)}</h3>
              </div>
              <StatusBadge variant={statusVariantForEvent(selected)} label={selected.decision || 'Recorded'} />
            </div>
            <dl className="detail-list">
              <div><dt>Timestamp</dt><dd>{selected.timestamp ? new Date(selected.timestamp).toLocaleString() : 'Unavailable'}</dd></div>
              <div><dt>Event ID</dt><dd><code>{selected.event_id || 'Unavailable'}</code></dd></div>
              <div><dt>Request ID</dt><dd><code>{selected.request_id || 'Not correlated'}</code></dd></div>
              <div><dt>Agent</dt><dd>{selected.agent_id || 'Unavailable'}</dd></div>
              <div><dt>Operation</dt><dd>{selected.operation || 'Unavailable'}</dd></div>
              <div><dt>Resource kind</dt><dd>{selected.resource_kind || 'Unavailable'}</dd></div>
              <div><dt>Reason code</dt><dd>{selected.reason_code || 'Unavailable'}</dd></div>
            </dl>
            <div className="detail-section">
              <h4>Matched policy rules</h4>
              {selected.matched_rule_ids?.length
                ? <div className="rule-chip-list">{selected.matched_rule_ids.map((rule) => <code key={rule}>{rule}</code>)}</div>
                : <p className="unavailable-copy">No matched rule identifiers were recorded.</p>}
            </div>
            <div className="detail-section">
              <h4>Hash fingerprints</h4>
              {[
                { label: 'Previous hash', value: selected.previous_hash },
                { label: 'Current hash', value: selected.current_hash },
              ].map(({ label, value }) => (
                <div className="hash-block" key={label}>
                  <span>{label}</span>
                  <code>{value || 'Unavailable'}</code>
                  {value && <button type="button" onClick={() => copyFingerprint(value)} aria-label={`Copy ${label}`}><Copy size={13} /></button>}
                </div>
              ))}
            </div>
            {verification?.chain_valid && (
              <div className="inline-notice inline-notice--success">
                <ShieldCheck size={15} />
                This event is within a chain that passed full verification.
              </div>
            )}
          </div>
        )}
      </DetailDrawer>
    </div>
  );
}
