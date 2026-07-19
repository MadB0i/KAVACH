import { useEffect, useState, useCallback } from 'react';
import { getApprovals, approveApproval, denyApproval } from '../api';
import type { ApprovalRecord } from '../types';
import { useAuth } from '../context/useAuth';
import PageHeader from '../components/PageHeader';
import DataTable from '../components/DataTable';
import EmptyState from '../components/EmptyState';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import ConfirmDialog from '../components/ConfirmDialog';

export default function PendingApprovals() {
  const [approvals, setApprovals] = useState<ApprovalRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);
  const [confirmAction, setConfirmAction] = useState<{ type: 'approve' | 'deny'; id: string; summary: string } | null>(null);
  const { actor } = useAuth();

  const fetchApprovals = useCallback(async () => {
    try {
      const data = await getApprovals();
      setApprovals(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load approvals');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchApprovals();
    const interval = setInterval(fetchApprovals, 5000);
    return () => clearInterval(interval);
  }, [fetchApprovals]);

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message });
    setTimeout(() => setToast(null), 4000);
  };

  const handleApprove = async (id: string) => {
    setActionLoading(id);
    try {
      await approveApproval(id, actor || 'admin');
      showToast('success', 'Approval granted');
      setConfirmAction(null);
      fetchApprovals();
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Failed to approve');
    } finally {
      setActionLoading(null);
    }
  };

  const handleDeny = async (id: string, reason?: string) => {
    setActionLoading(id);
    try {
      await denyApproval(id, actor || 'admin', reason);
      showToast('success', 'Approval denied');
      setConfirmAction(null);
      fetchApprovals();
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Failed to deny');
    } finally {
      setActionLoading(null);
    }
  };

  const truncate = (s?: string, max = 40): string => {
    if (!s) return '\u2014';
    if (s.length > max) return s.slice(0, max - 3) + '...';
    return s;
  };

  if (loading) return <LoadingState message="Loading approvals..." />;
  if (error) return <ErrorState title="Failed to load approvals" message={error} onRetry={fetchApprovals} />;

  return (
    <div className="page">
      <PageHeader
        title="Pending Approvals"
        subtitle={`${approvals.length} approval${approvals.length !== 1 ? 's' : ''}`}
      />

      {toast && (
        <div className={`toast toast--${toast.type}`} role="alert">
          {toast.message}
        </div>
      )}

      {approvals.length === 0 ? (
        <EmptyState icon={'\u2713'} title="No Pending Approvals" description="All requests have been processed." />
      ) : (
        <DataTable
          columns={[
            { key: 'id', header: 'Approval ID', className: 'cell-mono cell-truncate', render: (a) => truncate(a.approval_id, 18) },
            { key: 'request_id', header: 'Request ID', className: 'cell-mono cell-truncate', render: (a) => truncate(a.request_id, 16) },
            { key: 'operation', header: 'Operation', render: (a) => a.operation || '\u2014' },
            { key: 'resource', header: 'Resource Kind', render: (a) => a.resource_kind || '\u2014' },
            { key: 'summary', header: 'Summary', className: 'cell-truncate', render: (a) => truncate(a.summary, 50) },
            { key: 'created', header: 'Created', render: (a) => a.created_at ? new Date(a.created_at).toLocaleString() : '\u2014' },
            { key: 'actions', header: 'Actions', className: 'cell-actions', render: (a) => (
              <>
                <button
                  className="btn btn--success btn--sm"
                  onClick={() => setConfirmAction({ type: 'approve', id: a.approval_id, summary: a.summary || '' })}
                  disabled={actionLoading === a.approval_id}
                  aria-label={`Approve ${a.approval_id}`}
                >
                  Approve
                </button>
                <button
                  className="btn btn--danger btn--sm"
                  onClick={() => setConfirmAction({ type: 'deny', id: a.approval_id, summary: a.summary || '' })}
                  disabled={actionLoading === a.approval_id}
                  aria-label={`Deny ${a.approval_id}`}
                >
                  Deny
                </button>
              </>
            )},
          ]}
          data={approvals}
          keyField={(a) => a.approval_id}
          emptyTitle="No Pending Approvals"
          emptyDescription="All requests have been processed."
        />
      )}

      {confirmAction?.type === 'approve' && (
        <ConfirmDialog
          open
          title="Approve Request"
          message={`Are you sure you want to approve this request?${confirmAction.summary ? ` Summary: ${truncate(confirmAction.summary, 60)}` : ''}`}
          confirmLabel="Approve"
          confirmVariant="primary"
          onConfirm={() => handleApprove(confirmAction.id)}
          onCancel={() => setConfirmAction(null)}
        />
      )}

      {confirmAction?.type === 'deny' && (
        <ConfirmDialog
          open
          title="Deny Request"
          message={`Are you sure you want to deny this request?${confirmAction.summary ? ` Summary: ${truncate(confirmAction.summary, 60)}` : ''}`}
          confirmLabel="Deny"
          confirmVariant="danger"
          showReason
          onConfirm={(reason) => handleDeny(confirmAction.id, reason)}
          onCancel={() => setConfirmAction(null)}
        />
      )}
    </div>
  );
}
