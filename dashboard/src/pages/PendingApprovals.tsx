import { useEffect, useState, useCallback } from 'react';
import { getApprovals, approveApproval, denyApproval } from '../api';
import type { ApprovalRecord } from '../types';
import { useAuth } from '../context/AuthContext';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import EmptyState from '../components/EmptyState';
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
      showToast('success', 'Approval granted successfully');
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

  const truncateSummary = (s?: string): string => {
    if (!s) return '-';
    if (s.length > 80) return s.slice(0, 77) + '...';
    return s;
  };

  if (loading) return <LoadingState message="Loading approvals..." />;
  if (error) return <ErrorState title="Failed to load approvals" message={error} onRetry={fetchApprovals} />;

  return (
    <div className="page">
      <h2 className="page__title">Pending Approvals</h2>

      {toast && (
        <div className={`toast toast--${toast.type}`} role="alert">
          {toast.message}
        </div>
      )}

      {approvals.length === 0 ? (
        <EmptyState icon={'\u2713'} title="No Pending Approvals" description="All requests have been processed." />
      ) : (
        <div className="table-container">
          <table className="table" role="table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Request ID</th>
                <th>Operation</th>
                <th>Resource</th>
                <th>Summary</th>
                <th>Created</th>
                <th>Expires</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {approvals.map((a) => (
                <tr key={a.id}>
                  <td className="cell-mono" title={a.id}>{a.id.slice(0, 8)}...</td>
                  <td className="cell-mono" title={a.request_id}>{a.request_id?.slice(0, 12)}...</td>
                  <td>{a.operation || '-'}</td>
                  <td>{a.resource || '-'}</td>
                  <td title={a.summary}>{truncateSummary(a.summary)}</td>
                  <td>{a.created_at ? new Date(a.created_at).toLocaleString() : '-'}</td>
                  <td>{a.expires_at ? new Date(a.expires_at).toLocaleString() : '-'}</td>
                  <td className="cell-actions">
                    <button
                      className="btn btn--success btn--sm"
                      onClick={() => setConfirmAction({ type: 'approve', id: a.id, summary: a.summary || '' })}
                      disabled={actionLoading === a.id}
                      aria-label={`Approve approval ${a.id}`}
                    >
                      Approve
                    </button>
                    <button
                      className="btn btn--danger btn--sm"
                      onClick={() => setConfirmAction({ type: 'deny', id: a.id, summary: a.summary || '' })}
                      disabled={actionLoading === a.id}
                      aria-label={`Deny approval ${a.id}`}
                    >
                      Deny
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {confirmAction?.type === 'approve' && (
        <ConfirmDialog
          open
          title="Approve Request"
          message={`Are you sure you want to approve this request? ${confirmAction.summary ? `Summary: ${truncateSummary(confirmAction.summary)}` : ''}`}
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
          message={`Are you sure you want to deny this request? ${confirmAction.summary ? `Summary: ${truncateSummary(confirmAction.summary)}` : ''}`}
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
