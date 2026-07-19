import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  CircleGauge,
  Clock3,
  FileCheck2,
  FileClock,
  HeartPulse,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { getApprovals, getAuditEvents, getHealth, getPolicies, getReady, getStatus, verifyAudit } from '../api';
import type {
  ApprovalRecord,
  AuditEvent,
  AuditVerifyResult,
  HealthStatus,
  PolicyInfo,
  ReadyStatus,
  StatusInfo,
} from '../types';
import EmptyState from '../components/EmptyState';
import EventTimeline from '../components/EventTimeline';
import HealthIndicator from '../components/HealthIndicator';
import LoadingSkeleton from '../components/LoadingSkeleton';
import PageHeader from '../components/PageHeader';
import RiskBadge from '../components/RiskBadge';
import SectionCard from '../components/SectionCard';
import SecurityMetricCard from '../components/SecurityMetricCard';
import StatusBadge from '../components/StatusBadge';
import { healthStateFrom, riskFromOperation, type HealthState } from '../utils/presentation';

interface OverviewData {
  approvals: ApprovalRecord[];
  events: AuditEvent[];
  policies: PolicyInfo[];
  health: HealthStatus | null;
  ready: ReadyStatus | null;
  status: StatusInfo | null;
  audit: AuditVerifyResult | null;
}

const emptyData: OverviewData = {
  approvals: [],
  events: [],
  policies: [],
  health: null,
  ready: null,
  status: null,
  audit: null,
};

function isAllowed(event: AuditEvent): boolean {
  return `${event.decision || ''} ${event.category}`.toLowerCase().includes('allow')
    || event.category === 'ExecutionSucceeded';
}

function isDenied(event: AuditEvent): boolean {
  const value = `${event.decision || ''} ${event.category}`.toLowerCase();
  return value.includes('deny') || value.includes('reject') || value.includes('fail');
}

function isApproval(event: AuditEvent): boolean {
  return event.category.toLowerCase().includes('approval');
}

function formatDuration(seconds?: number): string {
  if (seconds === undefined) return 'Unavailable';
  if (seconds < 60) return `${seconds}s`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

function RequestTrend({ events }: { events: AuditEvent[] }) {
  const buckets = useMemo(() => {
    const sorted = [...events].sort((a, b) => a.sequence - b.sequence);
    if (sorted.length < 2) return [];
    const bucketCount = Math.min(10, Math.max(4, Math.ceil(sorted.length / 12)));
    const size = Math.ceil(sorted.length / bucketCount);
    return Array.from({ length: bucketCount }, (_, index) => {
      const slice = sorted.slice(index * size, (index + 1) * size);
      return {
        allow: slice.filter(isAllowed).length,
        deny: slice.filter(isDenied).length,
        approval: slice.filter(isApproval).length,
        total: slice.length,
        label: slice.length > 0 && slice[slice.length - 1]?.timestamp
          ? new Date(slice[slice.length - 1]!.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          : `Batch ${index + 1}`,
      };
    }).filter((bucket) => bucket.total > 0);
  }, [events]);

  if (buckets.length === 0) {
    return (
      <EmptyState
        compact
        icon={Activity}
        title="No request trend yet"
        description="Evaluate a tool request through the gateway to start building a real activity trend."
      />
    );
  }

  const max = Math.max(...buckets.map((bucket) => bucket.total), 1);
  return (
    <div className="request-trend" aria-label="Request outcomes from available audit data">
      <div className="request-trend__legend">
        <span><i className="legend-dot legend-dot--allow" />Allowed</span>
        <span><i className="legend-dot legend-dot--deny" />Denied</span>
        <span><i className="legend-dot legend-dot--approval" />Approval</span>
      </div>
      <div className="request-trend__chart">
        {buckets.map((bucket, index) => (
          <div className="request-trend__column" key={`${bucket.label}-${index}`}>
            <div className="request-trend__bar" style={{ height: `${Math.max(12, (bucket.total / max) * 100)}%` }}>
              {bucket.allow > 0 && <span className="request-trend__segment request-trend__segment--allow" style={{ flex: bucket.allow }} />}
              {bucket.deny > 0 && <span className="request-trend__segment request-trend__segment--deny" style={{ flex: bucket.deny }} />}
              {bucket.approval > 0 && <span className="request-trend__segment request-trend__segment--approval" style={{ flex: bucket.approval }} />}
              <span className="sr-only">{bucket.label}: {bucket.total} events</span>
            </div>
            <span className="request-trend__label">{bucket.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Overview() {
  const [data, setData] = useState<OverviewData>(emptyData);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const fetchOverview = useCallback(async (manual = false) => {
    if (manual) setRefreshing(true);
    else setLoading(true);

    const baseResults = await Promise.allSettled([
      getApprovals(),
      getPolicies(),
      getHealth(),
      getReady(),
      getStatus(),
      verifyAudit(),
    ]);

    const [approvalResult, policyResult, healthResult, readyResult, statusResult, auditResult] = baseResults;
    const audit = auditResult.status === 'fulfilled' ? auditResult.value : null;
    const after = audit?.event_count && audit.event_count > 250 ? audit.event_count - 250 : undefined;
    const eventResult = await Promise.allSettled([getAuditEvents({ after, limit: 250 })]);

    const next: OverviewData = {
      approvals: approvalResult.status === 'fulfilled' ? approvalResult.value : [],
      policies: policyResult.status === 'fulfilled' ? policyResult.value : [],
      health: healthResult.status === 'fulfilled' ? healthResult.value : null,
      ready: readyResult.status === 'fulfilled' ? readyResult.value : null,
      status: statusResult.status === 'fulfilled' ? statusResult.value : null,
      audit,
      events: eventResult[0].status === 'fulfilled' ? eventResult[0].value : [],
    };

    const failures = [...baseResults, ...eventResult].filter((result) => result.status === 'rejected');
    setData(next);
    setError(failures.length === baseResults.length + eventResult.length
      ? 'The gateway did not return any overview data.'
      : failures.length > 0
        ? `${failures.length} data source${failures.length === 1 ? '' : 's'} unavailable; showing verified results from the remaining APIs.`
        : null);
    setLastRefresh(new Date());
    setLoading(false);
    setRefreshing(false);
  }, []);

  useEffect(() => {
    fetchOverview();
    const interval = window.setInterval(() => fetchOverview(), 15000);
    return () => window.clearInterval(interval);
  }, [fetchOverview]);

  const pending = data.approvals.filter((approval) => (approval.state || approval.status || 'pending').toLowerCase() === 'pending');
  const allowed = data.events.filter(isAllowed).length;
  const denied = data.events.filter(isDenied).length;
  const approvalRequired = data.events.filter((event) => event.category === 'ApprovalRequested').length;
  const uptime = data.status?.uptime_seconds ?? data.status?.uptime;

  const componentStates: Array<{ label: string; state: HealthState; detail: string }> = [
    { label: 'Gateway API', state: healthStateFrom(data.health?.status), detail: 'Request ingress' },
    { label: 'Filesystem', state: healthStateFrom(data.ready?.adapter_filesystem ?? data.ready?.adapters?.filesystem), detail: 'Path enforcement' },
    { label: 'Command', state: healthStateFrom(data.ready?.adapter_command ?? data.ready?.adapters?.command), detail: 'Process controls' },
    { label: 'Network', state: healthStateFrom(data.ready?.adapter_network ?? data.ready?.adapters?.network), detail: 'SSRF controls' },
    { label: 'Audit chain', state: data.audit ? (data.audit.chain_valid ? 'healthy' : 'error') : 'unavailable', detail: 'Integrity ledger' },
    { label: 'Approvals', state: healthStateFrom(data.ready?.approval_available ?? data.health?.approval_store), detail: 'Human control' },
  ];
  const observed = componentStates.filter((component) => component.state !== 'unavailable');
  const healthyCount = observed.filter((component) => component.state === 'healthy').length;
  const posturePercent = observed.length > 0 ? Math.round((healthyCount / observed.length) * 100) : null;
  const postureState: HealthState = observed.length === 0
    ? 'unavailable'
    : observed.some((component) => component.state === 'error')
      ? 'error'
      : observed.some((component) => component.state === 'warning')
        ? 'warning'
        : 'healthy';

  const latestEvents = [...data.events].sort((a, b) => b.sequence - a.sequence).slice(0, 7);

  return (
    <div className="page overview-page">
      <PageHeader
        eyebrow="Security operations"
        title="Runtime Overview"
        icon={CircleGauge}
        subtitle="Live enforcement posture from the local KAVACH gateway."
        actions={
          <div className="page-refresh">
            <span>{lastRefresh ? `Updated ${lastRefresh.toLocaleTimeString()}` : 'Awaiting refresh'}</span>
            <button className="btn btn--secondary btn--sm" type="button" onClick={() => fetchOverview(true)} disabled={refreshing}>
              <RefreshCw className={refreshing ? 'spin' : ''} size={14} />
              Refresh
            </button>
          </div>
        }
      />

      {error && <div className="inline-notice inline-notice--warning" role="status"><ShieldQuestion size={15} />{error}</div>}

      <section className={`posture-hero posture-hero--${postureState}`}>
        <div className="posture-hero__signal">
          <div className="posture-hero__ring" style={{ '--posture': posturePercent ?? 0 } as React.CSSProperties}>
            <span>{posturePercent === null ? '?' : posturePercent}</span>
            <small>{posturePercent === null ? 'unknown' : '%'}</small>
          </div>
          <div>
            <span className="posture-hero__eyebrow">Observed security posture</span>
            <h3>{postureState === 'healthy' ? 'Controls operating normally' : postureState === 'unavailable' ? 'Posture unavailable' : 'Attention required'}</h3>
            <p>{observed.length > 0 ? `${healthyCount} of ${observed.length} observable runtime controls report healthy.` : 'The gateway has not returned enough component state to calculate posture.'}</p>
          </div>
        </div>
        <div className="posture-hero__runtime">
          <HealthIndicator state={healthStateFrom(data.health?.status)} label={data.status?.service || 'Gateway runtime'} />
          <span><strong>{data.status?.version ? `v${data.status.version}` : 'Version unavailable'}</strong> · uptime {formatDuration(uptime)}</span>
          <span className="posture-hero__bind">{data.status?.bind || data.status?.bind_address || 'Bind address unavailable'}</span>
        </div>
      </section>

      <div className="security-metric-grid">
        <SecurityMetricCard label="Allowed" value={allowed} detail={`Within ${data.events.length} loaded events`} icon={CheckCircle2} tone="success" loading={loading} />
        <SecurityMetricCard label="Denied" value={denied} detail="Explicit deny or failed execution" icon={ShieldAlert} tone={denied > 0 ? 'danger' : 'default'} loading={loading} />
        <SecurityMetricCard label="Approval required" value={approvalRequired} detail={`${pending.length} currently pending`} icon={FileClock} tone={pending.length > 0 ? 'warning' : 'default'} loading={loading} />
        <SecurityMetricCard label="Policies loaded" value={data.policies.length} detail={data.policies.length > 0 ? 'Default-deny policy set' : 'No policy metadata returned'} icon={ShieldCheck} tone={data.policies.length > 0 ? 'accent' : 'warning'} loading={loading} />
        <SecurityMetricCard label="Runtime" value={healthStateFrom(data.health?.status) === 'healthy' ? 'Active' : 'Unavailable'} detail={`Uptime ${formatDuration(uptime)}`} icon={HeartPulse} tone={healthStateFrom(data.health?.status) === 'healthy' ? 'success' : 'warning'} loading={loading} />
      </div>

      <div className="overview-grid overview-grid--primary">
        <SectionCard
          title="Request outcome trend"
          actions={<span className="section-card__meta">{data.events.length} real audit events</span>}
        >
          {loading ? <LoadingSkeleton type="card" count={1} /> : <RequestTrend events={data.events} />}
        </SectionCard>

        <section className="integrity-card">
          <div className="integrity-card__icon">
            {data.audit?.chain_valid ? <FileCheck2 size={23} /> : <ShieldAlert size={23} />}
          </div>
          <span className="integrity-card__eyebrow">Audit-chain integrity</span>
          <h3>{data.audit ? (data.audit.chain_valid ? 'Cryptographically valid' : 'Verification failed') : 'Verification unavailable'}</h3>
          <p>
            {data.audit
              ? `${data.audit.event_count ?? 0} events verified through sequence ${data.audit.verified_to ?? 0}.`
              : 'The verification API did not return an integrity result.'}
          </p>
          <div className="integrity-card__footer">
            <StatusBadge
              variant={data.audit ? (data.audit.chain_valid ? 'success' : 'error') : 'neutral'}
              label={data.audit ? (data.audit.chain_valid ? 'Chain intact' : 'Investigate') : 'Unavailable'}
            />
            <Link to="/audit-verify">Open verification <ArrowRight size={13} /></Link>
          </div>
        </section>
      </div>

      <section className="component-strip" aria-label="Runtime component health">
        {componentStates.map((component) => (
          <div className="component-strip__item" key={component.label}>
            <HealthIndicator state={loading ? 'loading' : component.state} label={component.label} compact />
            <span>{component.detail}</span>
          </div>
        ))}
      </section>

      <div className="overview-grid overview-grid--secondary">
        <SectionCard
          title="Recent security events"
          actions={<Link className="text-link" to="/audit">View timeline <ArrowRight size={13} /></Link>}
        >
          {loading ? (
            <LoadingSkeleton type="row" count={6} />
          ) : latestEvents.length > 0 ? (
            <EventTimeline events={latestEvents} compact />
          ) : (
            <EmptyState
              compact
              icon={Activity}
              title="No security activity recorded"
              description="Send a request to POST /api/requests/evaluate. KAVACH will record the resulting policy decision here."
              action={<Link className="btn btn--secondary btn--sm" to="/live-requests">Open live monitor</Link>}
            />
          )}
        </SectionCard>

        <SectionCard
          title="Pending approvals"
          actions={<Link className="text-link" to="/approvals">Review queue <ArrowRight size={13} /></Link>}
        >
          {loading ? (
            <LoadingSkeleton type="row" count={4} />
          ) : pending.length > 0 ? (
            <div className="approval-compact-list">
              {pending.slice(0, 5).map((approval) => (
                <div className="approval-compact" key={approval.approval_id || approval.id}>
                  <div>
                    <strong>{approval.operation || 'Operation unavailable'}</strong>
                    <span>{approval.summary || approval.request_id}</span>
                  </div>
                  <RiskBadge level={riskFromOperation(approval.operation)} />
                  <span className="approval-compact__expiry">
                    <Clock3 size={12} />
                    {approval.expires_at ? new Date(approval.expires_at).toLocaleTimeString() : 'Expiry unavailable'}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              compact
              icon={ShieldCheck}
              title="Approval queue clear"
              description="Requests requiring human authorization will appear here with their expiry and risk context."
            />
          )}
        </SectionCard>
      </div>
    </div>
  );
}
