import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Check,
  Clock3,
  FileClock,
  RefreshCw,
  ShieldCheck,
  UserRound,
  X,
} from 'lucide-react';
import { approveApproval, denyApproval, getApprovals } from '../api';
import type { ApprovalRecord } from '../types';
import { useAuth } from '../context/useAuth';
import ConfirmDialog from '../components/ConfirmDialog';
import DataTable from '../components/DataTable';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import LoadingSkeleton from '../components/LoadingSkeleton';
import PageHeader from '../components/PageHeader';
import RiskBadge from '../components/RiskBadge';
import StatusBadge from '../components/StatusBadge';
import { riskFromOperation } from '../utils/presentation';

interface ConfirmAction {
  type: 'approve' | 'deny';
  approval: ApprovalRecord;
}

function approvalId(approval: ApprovalRecord): string {
  return approval.approval_id || approval.id || '';
}

function formatCountdown(expiresAt?: string, now = Date.now()): { label: string; urgent: boolean } {
  if (!expiresAt) return { label: 'Expiry unavailable', urgent: false };
  const remaining = new Date(expiresAt).getTime() - now;
  if (!Number.isFinite(remaining)) return { label: 'Expiry unavailable', urgent: false };
  if (remaining <= 0) return { label: 'Expired', urgent: true };
  const seconds = Math.floor(remaining / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  if (hours > 0) return { label: `${hours}h ${minutes % 60}m remaining`, urgent: hours < 1 };
  if (minutes > 0) return { label: `${minutes}m ${seconds % 60}s remaining`, urgent: minutes < 5 };
  return { label: `${seconds}s remaining`, urgent: true };
}

export default function PendingApprovals() {
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [confirmAction, setConfirmAction] = useState<ConfirmAction | null>(null);
  const [now, setNow] = useState(Date.now());
  const { actor } = useAuth();

  const fetchApprovals = useCallback(async (manual = false) => {
    if (manual) setRefreshing(true);
    try {
      const records = await getApprovals();
      setApprovals(records.filter((approval) => (approval.state || approval.status || 'pending').toLowerCase() === 'pending'));
      setError(null);
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : 'Failed to load approvals');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchApprovals();
    const poll = window.setInterval(() => fetchApprovals(), 5000);
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      window.clearInterval(poll);
      window.clearInterval(clock);
    };
  }, [fetchApprovals]);

  const sortedApprovals = useMemo(
    () => [...approvals].sort((a, b) => new Date(a.expires_at || 0).getTime() - new Date(b.expires_at || 0).getTime()),
    [approvals],
  );

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message });
    window.setTimeout(() => setToast(null), 4000);
  };

  const handleApprove = async (approval: ApprovalRecord) => {
    const id = approvalId(approval);
    setActionLoading(id);
    try {
      await approveApproval(id, actor || 'operator');
      showToast('success', 'Request approved. Sensitive approval material was not rendered or stored.');
      setConfirmAction(null);
      await fetchApprovals();
    } catch (actionError) {
      showToast('error', actionError instanceof Error ? actionError.message : 'Approval failed');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeny = async (approval: ApprovalRecord, reason?: string) => {
    const id = approvalId(approval);
    setActionLoading(id);
    try {
      await denyApproval(id, actor || 'operator', reason);
      showToast('success', 'Request denied and removed from the pending queue.');
      setConfirmAction(null);
      await fetchApprovals();
    } catch (actionError) {
      showToast('error', actionError instanceof Error ? actionError.message : 'Denial failed');
    } finally {
      setActionLoading(null);
    }
  };

  if (error && approvals.length === 0 && !loading) {
    return <ErrorState title="Approval queue unavailable" message={error} onRetry={() => fetchApprovals(true)} />;
  }

  return (
    <div className="page approvals-page">
      <PageHeader
        eyebrow="Human authorization"
        title="Pending Approvals"
        icon={FileClock}
        subtitle="Review high-impact requests before a short-lived permit can be issued."
        actions={
          <div className="page-refresh">
            <StatusBadge variant={approvals.length > 0 ? 'warning' : 'success'} label={`${approvals.length} pending`} />
            <button className="btn btn--secondary btn--sm" type="button" onClick={() => fetchApprovals(true)} disabled={refreshing}>
              <RefreshCw className={refreshing ? 'spin' : ''} size={14} />
              Refresh
            </button>
          </div>
        }
      />

      {toast && <div className={`toast toast--${toast.type}`} role="alert">{toast.message}</div>}
      {error && <div className="inline-notice inline-notice--warning" role="status">{error}</div>}

      <div className="approval-summary-strip">
        <div><ShieldCheck size={16} /><span><strong>Fail-closed queue</strong> Requests remain blocked until an operator decides.</span></div>
        <div><UserRound size={15} /><span>Acting as <strong>{actor || 'operator'}</strong></span></div>
      </div>

      {loading ? (
        <div className="surface-panel"><LoadingSkeleton type="row" count={7} /></div>
      ) : sortedApprovals.length === 0 ? (
        <EmptyState
          icon={ShieldCheck}
          title="Approval queue clear"
          description="No request is waiting for human authorization. New approval-required operations will appear here automatically."
        />
      ) : (
        <DataTable
          data={sortedApprovals}
          keyField={(approval) => approvalId(approval)}
          rowLabel={(approval) => `${approval.operation || 'Unknown operation'} approval for ${approval.request_id}`}
          columns={[
            {
              key: 'risk',
              header: 'Risk',
              render: (approval) => <RiskBadge level={riskFromOperation(approval.operation)} />,
            },
            {
              key: 'request',
              header: 'Request',
              render: (approval) => (
                <div className="approval-request-cell">
                  <strong>{approval.operation || 'Operation unavailable'}</strong>
                  <code title={approval.request_id}>{approval.request_id}</code>
                </div>
              ),
            },
            {
              key: 'agent',
              header: 'Agent',
              render: (approval) => (
                <div className="approval-agent-cell">
                  <UserRound size={14} />
                  <span>{typeof approval.agent_id === 'string' ? approval.agent_id : 'Agent unavailable'}</span>
                </div>
              ),
            },
            {
              key: 'resource',
              header: 'Resource',
              render: (approval) => (
                <div className="approval-resource-cell">
                  <strong>{approval.resource_kind || approval.resource || 'Resource unavailable'}</strong>
                  <span>{approval.summary || 'No approval reason was recorded.'}</span>
                </div>
              ),
            },
            {
              key: 'rules',
              header: 'Policy reason',
              render: (approval) => approval.matched_rule_ids?.length
                ? <div className="rule-chip-list">{approval.matched_rule_ids.slice(0, 2).map((rule) => <code key={rule}>{rule}</code>)}</div>
                : <span className="unavailable-label">Rule unavailable</span>,
            },
            {
              key: 'expiry',
              header: 'Expiry',
              render: (approval) => {
                const countdown = formatCountdown(approval.expires_at, now);
                return (
                  <span className={`expiry-countdown ${countdown.urgent ? 'expiry-countdown--urgent' : ''}`}>
                    <Clock3 size={13} />
                    {countdown.label}
                  </span>
                );
              },
            },
            {
              key: 'actions',
              header: 'Decision',
              className: 'cell-actions',
              render: (approval) => {
                const id = approvalId(approval);
                return (
                  <div className="approval-actions">
                    <button
                      className="btn btn--success btn--sm"
                      type="button"
                      onClick={() => setConfirmAction({ type: 'approve', approval })}
                      disabled={actionLoading === id}
                      aria-label={`Approve request ${approval.request_id}`}
                    >
                      <Check size={14} /> Approve
                    </button>
                    <button
                      className="btn btn--danger-ghost btn--sm"
                      type="button"
                      onClick={() => setConfirmAction({ type: 'deny', approval })}
                      disabled={actionLoading === id}
                      aria-label={`Deny request ${approval.request_id}`}
                    >
                      <X size={14} /> Deny
                    </button>
                  </div>
                );
              },
            },
          ]}
        />
      )}

      <ConfirmDialog
        open={confirmAction?.type === 'approve'}
        title="Authorize this request?"
        message="KAVACH will mark this approval as granted. The request remains bound to its original operation and expiry."
        confirmLabel="Approve request"
        confirmVariant="primary"
        onConfirm={() => confirmAction && handleApprove(confirmAction.approval)}
        onCancel={() => setConfirmAction(null)}
      >
        {confirmAction && (
          <div className="decision-summary">
            <RiskBadge level={riskFromOperation(confirmAction.approval.operation)} />
            <div><span>Operation</span><strong>{confirmAction.approval.operation || 'Unavailable'}</strong></div>
            <div><span>Request</span><code>{confirmAction.approval.request_id}</code></div>
          </div>
        )}
      </ConfirmDialog>

      <ConfirmDialog
        open={confirmAction?.type === 'deny'}
        title="Deny this request?"
        message="The pending request will be rejected. Record a concise reason for the audit trail."
        confirmLabel="Deny request"
        confirmVariant="danger"
        showReason
        onConfirm={(reason) => confirmAction && handleDeny(confirmAction.approval, reason)}
        onCancel={() => setConfirmAction(null)}
      >
        {confirmAction && (
          <div className="decision-summary">
            <RiskBadge level={riskFromOperation(confirmAction.approval.operation)} />
            <div><span>Operation</span><strong>{confirmAction.approval.operation || 'Unavailable'}</strong></div>
            <div><span>Request</span><code>{confirmAction.approval.request_id}</code></div>
          </div>
        )}
      </ConfirmDialog>
    </div>
  );
}
