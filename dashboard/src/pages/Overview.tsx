import { useEffect, useState, useCallback } from 'react';
import { getApprovals, getAuditEvents, getPolicies, getHealth, getStatus } from '../api';
import type { ApprovalRecord, AuditEvent, PolicyInfo, HealthStatus, StatusInfo } from '../types';
import PageHeader from '../components/PageHeader';
import MetricCard from '../components/MetricCard';
import SectionCard from '../components/SectionCard';
import StatusBadge from '../components/StatusBadge';
import LoadingSkeleton from '../components/LoadingSkeleton';

interface LoadInfo {
  loading: boolean;
  error: string | null;
}

export default function Overview() {
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [policies, setPolicies] = useState<PolicyInfo[]>([]);
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [statusInfo, setStatusInfo] = useState<StatusInfo | null>(null);
  const [loadState, setLoadState] = useState<Record<string, LoadInfo>>({
    approvals: { loading: true, error: null },
    audit: { loading: true, error: null },
    policies: { loading: true, error: null },
    health: { loading: true, error: null },
    status: { loading: true, error: null },
  });

  const fetchAll = useCallback(async () => {
    const fetches = [
      { key: 'approvals', fn: getApprovals(), setter: setApprovals },
      { key: 'audit', fn: getAuditEvents({ limit: 5 }), setter: setAuditEvents },
      { key: 'policies', fn: getPolicies(), setter: setPolicies },
      { key: 'health', fn: getHealth(), setter: setHealth },
      { key: 'status', fn: getStatus(), setter: setStatusInfo },
    ];
    for (const f of fetches) {
      setLoadState((prev) => ({ ...prev, [f.key]: { loading: true, error: null } }));
      try {
        const data = await f.fn;
        (f.setter as (d: unknown) => void)(data);
        setLoadState((prev) => ({ ...prev, [f.key]: { loading: false, error: null } }));
      } catch (err) {
        setLoadState((prev) => ({
          ...prev,
          [f.key]: { loading: false, error: err instanceof Error ? err.message : 'Unknown error' },
        }));
      }
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 10000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  const ls = loadState;

  const allowedCount = auditEvents.filter((e) => e.decision === 'allow' || e.decision === 'allowed').length;
  const deniedCount = auditEvents.filter((e) => e.decision === 'deny' || e.decision === 'denied').length;
  const pendingCount = approvals.filter((a) => !a.status || a.status === 'pending').length;
  const healthOk = health?.status === 'ok' || health?.status === 'healthy';

  const getHealthVariant = (s?: string): 'success' | 'error' | 'info' => {
    if (!s) return 'info';
    const v = s.toLowerCase();
    if (v === 'ok' || v === 'healthy' || v === 'connected') return 'success';
    if (v === 'error' || v === 'down') return 'error';
    return 'info';
  };

  const getHealthLabel = (s?: string) => s || '\u2014';

  return (
    <div className="page">
      <PageHeader
        title="Overview"
        subtitle={
          statusInfo
            ? `${statusInfo.service} v${statusInfo.version || '?'} \u2014 Uptime: ${statusInfo.uptime !== undefined ? `${Math.floor(statusInfo.uptime / 60)}m` : '?'}`
            : undefined
        }
      />

      <div className="metric-grid">
        <MetricCard
          label="Posture"
          value={healthOk ? 'Healthy' : 'Unhealthy'}
          variant={healthOk ? 'success' : 'error'}
          loading={ls.health?.loading}
          error={ls.health?.error}
        />
        <MetricCard
          label="Allowed"
          value={allowedCount}
          variant="success"
          loading={ls.audit?.loading}
          error={ls.audit?.error}
        />
        <MetricCard
          label="Denied"
          value={deniedCount}
          variant="error"
          loading={ls.audit?.loading}
          error={ls.audit?.error}
        />
        <MetricCard
          label="Pending Approvals"
          value={pendingCount}
          variant={pendingCount > 0 ? 'warning' : 'success'}
          loading={ls.approvals?.loading}
          error={ls.approvals?.error}
        />
        <MetricCard
          label="Policies"
          value={policies.length}
          variant={policies.length > 0 ? 'info' : 'warning'}
          loading={ls.policies?.loading}
          error={ls.policies?.error}
        />
      </div>

      <SectionCard title="System Health" flush>
        {ls.health?.loading ? (
          <div style={{ padding: '16px 20px' }}>
            <LoadingSkeleton type="row" count={5} />
          </div>
        ) : (
          <div style={{ padding: '12px 20px', display: 'flex', flexWrap: 'wrap', gap: 20 }}>
            {[
              { label: 'API', status: health?.status },
              { label: 'Database', status: health?.database },
              { label: 'Policy Engine', status: health?.policy_engine },
              { label: 'Audit Store', status: health?.audit_store },
              { label: 'Approval Store', status: health?.approval_store },
            ].map((s) => (
              <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: '0.8125rem' }}>
                <span style={{ color: 'var(--color-text-muted)', fontWeight: 500, minWidth: 80 }}>{s.label}</span>
                <StatusBadge variant={getHealthVariant(s.status)} label={getHealthLabel(s.status)} />
              </div>
            ))}
          </div>
        )}
      </SectionCard>

      <SectionCard title="Recent Activity">
        {ls.audit?.loading ? (
          <LoadingSkeleton type="row" count={5} />
        ) : ls.audit?.error ? (
          <div style={{ color: 'var(--color-error-text)', fontSize: '0.8125rem' }}>{ls.audit.error}</div>
        ) : auditEvents.length === 0 ? (
          <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', textAlign: 'center', padding: 16 }}>
            No recent audit events
          </div>
        ) : (
          <div className="audit-mini-list">
            {auditEvents.map((ev) => (
              <div key={`${ev.sequence}-${ev.timestamp}`} className="audit-mini-item">
                <span className="audit-mini-item__time">
                  {ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : '?'}
                </span>
                <StatusBadge
                  variant={
                    ev.decision === 'allow' || ev.decision === 'allowed'
                      ? 'success'
                      : ev.decision === 'deny' || ev.decision === 'denied'
                        ? 'error'
                        : 'info'
                  }
                  label={ev.decision || ev.category || 'event'}
                />
                <span className="audit-mini-item__op">{ev.operation || '\u2014'}</span>
                <span className="audit-mini-item__req">{ev.request_id || '\u2014'}</span>
              </div>
            ))}
          </div>
        )}
      </SectionCard>

      <SectionCard title={`Pending Approvals (${pendingCount})`}>
        {ls.approvals?.loading ? (
          <LoadingSkeleton type="row" count={4} />
        ) : approvals.filter((a) => !a.status || a.status === 'pending').length === 0 ? (
          <div style={{ color: 'var(--color-text-muted)', fontSize: '0.8125rem', textAlign: 'center', padding: 16 }}>
            All clear \u2014 no pending approvals
          </div>
        ) : (
          <div className="audit-mini-list">
            {approvals
              .filter((a) => !a.status || a.status === 'pending')
              .slice(0, 5)
              .map((a) => (
                <div key={a.id} className="audit-mini-item">
                  <span className="audit-mini-item__time">
                    {a.created_at ? new Date(a.created_at).toLocaleDateString() : '?'}
                  </span>
                  <StatusBadge variant="warning" label="pending" />
                  <span className="audit-mini-item__op">{a.operation || '\u2014'}</span>
                  <span
                    className="audit-mini-item__req"
                    title={a.summary || ''}
                  >
                    {a.summary ? (a.summary.length > 40 ? a.summary.slice(0, 37) + '...' : a.summary) : a.request_id}
                  </span>
                </div>
              ))}
          </div>
        )}
      </SectionCard>
    </div>
  );
}
