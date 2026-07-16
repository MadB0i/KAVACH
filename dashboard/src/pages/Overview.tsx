import { useEffect, useState, useCallback } from 'react';
import { getApprovals, getAuditEvents, getPolicies, getHealth, getStatus } from '../api';
import type { ApprovalRecord, AuditEvent, PolicyInfo, HealthStatus, StatusInfo } from '../types';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import StatusBadge from '../components/StatusBadge';

interface LoadInfo {
  loading: boolean;
  error: string | null;
}

interface StatCard {
  title: string;
  value: string | number;
  variant: 'success' | 'warning' | 'error' | 'info';
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
  });

  const fetchAll = useCallback(async () => {
    const fetches = [
      { key: 'approvals', fn: getApprovals(), setter: setApprovals },
      { key: 'audit', fn: getAuditEvents({ limit: 5 }), setter: setAuditEvents },
      { key: 'policies', fn: getPolicies(), setter: setPolicies },
      { key: 'health', fn: getHealth(), setter: setHealth },
    ];
    for (const f of fetches) {
      setLoadState((prev) => ({ ...prev, [f.key]: { loading: true, error: null } }));
      try {
        const data = await f.fn;
        (f.setter as (d: unknown) => void)(data);
        setLoadState((prev) => ({ ...prev, [f.key]: { loading: false, error: null } }));
      } catch (err) {
        setLoadState((prev) => ({ ...prev, [f.key]: { loading: false, error: err instanceof Error ? err.message : 'Unknown error' } }));
      }
    }
    try {
      const si = await getStatus();
      setStatusInfo(si);
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 10000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  const ls = loadState as Record<string, LoadInfo>;
  const statCards: StatCard[] = [
    { title: 'Active Approvals', value: approvals.length, variant: approvals.length > 0 ? 'warning' : 'success', loading: ls.approvals?.loading ?? true, error: ls.approvals?.error ?? null },
    { title: 'Recent Audit Events', value: auditEvents.length, variant: 'info', loading: ls.audit?.loading ?? true, error: ls.audit?.error ?? null },
    { title: 'Policies Loaded', value: policies.length, variant: policies.length > 0 ? 'success' : 'warning', loading: ls.policies?.loading ?? true, error: ls.policies?.error ?? null },
    { title: 'System Health', value: health?.status || 'Unknown', variant: health?.status === 'ok' || health?.status === 'healthy' ? 'success' : 'error', loading: ls.health?.loading ?? true, error: ls.health?.error ?? null },
  ];

  const getHealthVariant = (s?: string): 'success' | 'error' => (s === 'ok' || s === 'healthy') ? 'success' : 'error';
  const getHealthLabel = (s?: string) => s || 'Unknown';

  return (
    <div className="page">
      <h2 className="page__title">Overview</h2>
      {statusInfo && (
        <p className="page__subtitle">
          {statusInfo.service} v{statusInfo.version || '?'} {'\u2014'} Uptime: {statusInfo.uptime !== undefined ? `${Math.floor(statusInfo.uptime / 60)}m` : '?'}
        </p>
      )}

      <div className="stat-grid">
        {statCards.map((card) => (
          <div key={card.title} className="stat-card">
            <h3 className="stat-card__title">{card.title}</h3>
            {card.loading ? (
              <LoadingState compact message="" />
            ) : card.error ? (
              <ErrorState title="Error" message={card.error} />
            ) : (
              <div className="stat-card__value">
                <StatusBadge variant={card.variant} label={String(card.value)} />
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="section">
        <h3 className="section__title">System Status</h3>
        <div className="health-grid">
          <div className="health-card">
            <span className="health-card__label">API</span>
            <StatusBadge variant={getHealthVariant(health?.status)} label={getHealthLabel(health?.status)} />
          </div>
          <div className="health-card">
            <span className="health-card__label">Database</span>
            <StatusBadge variant={getHealthVariant(health?.database)} label={getHealthLabel(health?.database)} />
          </div>
          <div className="health-card">
            <span className="health-card__label">Policy Engine</span>
            <StatusBadge variant={getHealthVariant(health?.policy_engine)} label={getHealthLabel(health?.policy_engine)} />
          </div>
          <div className="health-card">
            <span className="health-card__label">Audit Store</span>
            <StatusBadge variant={getHealthVariant(health?.audit_store)} label={getHealthLabel(health?.audit_store)} />
          </div>
          <div className="health-card">
            <span className="health-card__label">Approval Store</span>
            <StatusBadge variant={getHealthVariant(health?.approval_store)} label={getHealthLabel(health?.approval_store)} />
          </div>
        </div>
      </div>

      <div className="section">
        <h3 className="section__title">Recent Activity</h3>
        {ls.audit?.loading ? (
          <LoadingState message="Loading audit events..." />
        ) : ls.audit?.error ? (
          <ErrorState title="Error" message={ls.audit.error} onRetry={fetchAll} />
        ) : auditEvents.length === 0 ? (
          <div className="empty-state"><p>No recent audit events</p></div>
        ) : (
          <div className="audit-mini-list">
            {auditEvents.map((ev) => (
              <div key={`${ev.sequence}-${ev.timestamp}`} className="audit-mini-item">
                <span className="audit-mini-item__time">{ev.timestamp ? new Date(ev.timestamp).toLocaleTimeString() : '?'}</span>
                <StatusBadge
                  variant={ev.decision === 'allow' || ev.decision === 'allowed' ? 'success' : ev.decision === 'deny' || ev.decision === 'denied' ? 'error' : 'info'}
                  label={ev.decision || ev.category || 'event'}
                />
                <span className="audit-mini-item__op">{ev.operation || '-'}</span>
                <span className="audit-mini-item__req">{ev.request_id || '-'}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
