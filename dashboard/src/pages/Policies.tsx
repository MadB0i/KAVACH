import { useEffect, useState, useCallback } from 'react';
import { getPolicies, reloadPolicies } from '../api';
import type { PolicyInfo } from '../types';
import PageHeader from '../components/PageHeader';
import EmptyState from '../components/EmptyState';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import ConfirmDialog from '../components/ConfirmDialog';
import StatusBadge from '../components/StatusBadge';

export default function Policies() {
  const [policies, setPolicies] = useState<PolicyInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showReload, setShowReload] = useState(false);
  const [reloadPaths, setReloadPaths] = useState('');
  const [reloading, setReloading] = useState(false);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchPolicies = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getPolicies();
      setPolicies(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load policies');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPolicies();
  }, [fetchPolicies]);

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message });
    setTimeout(() => setToast(null), 4000);
  };

  const handleReload = async () => {
    setReloading(true);
    try {
      const paths = reloadPaths.split('\n').map((s) => s.trim()).filter(Boolean);
      await reloadPolicies(paths);
      showToast('success', 'Policies reloaded successfully');
      setShowReload(false);
      setReloadPaths('');
      fetchPolicies();
    } catch (err) {
      showToast('error', err instanceof Error ? err.message : 'Failed to reload policies');
    } finally {
      setReloading(false);
    }
  };

  if (loading) return <LoadingState message="Loading policies..." />;
  if (error) return <ErrorState title="Failed to load policies" message={error} onRetry={fetchPolicies} />;

  return (
    <div className="page">
      <PageHeader
        title="Policies"
        subtitle={`${policies.length} policy document${policies.length !== 1 ? 's' : ''} loaded`}
        actions={
          <button className="btn btn--primary" onClick={() => setShowReload(true)} aria-label="Reload policies">
            Reload
          </button>
        }
      />

      {toast && (
        <div className={`toast toast--${toast.type}`} role="alert">
          {toast.message}
        </div>
      )}

      {policies.length === 0 ? (
        <EmptyState icon={'\u2699'} title="No Policies" description="No policies are currently loaded." />
      ) : (
        <div className="policy-grid">
          {policies.map((p) => (
            <div key={p.policy_id} className="policy-card">
              <h3 className="policy-card__name">{p.policy_name || p.policy_id}</h3>
              <div className="policy-card__id">{p.policy_id}</div>
              <div className="policy-card__meta">
                <span><strong>Rules:</strong> {p.rule_count ?? '?'}</span>
                <span>
                  <strong>Default Effect:</strong>{' '}
                  <StatusBadge
                    variant={p.default_effect === 'allow' ? 'success' : p.default_effect === 'deny' ? 'error' : 'info'}
                    label={p.default_effect || 'unknown'}
                  />
                </span>
              </div>
            </div>
          ))}
        </div>
      )}

      <ConfirmDialog
        open={showReload}
        title="Reload Policies"
        message="Enter the policy file paths to reload (one per line):"
        confirmLabel={reloading ? 'Reloading...' : 'Reload'}
        confirmVariant="primary"
        onConfirm={handleReload}
        onCancel={() => { setShowReload(false); setReloadPaths(''); }}
      >
        <div className="modal__field">
          <label htmlFor="reload-paths" className="modal__label">Policy Paths</label>
          <textarea
            id="reload-paths"
            className="modal__textarea"
            value={reloadPaths}
            onChange={(e) => setReloadPaths(e.target.value)}
            placeholder={"./config/default-policy.toml\n./config/custom-policy.toml"}
            rows={4}
          />
        </div>
      </ConfirmDialog>
    </div>
  );
}
