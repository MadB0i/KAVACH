import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  FileCode2,
  FolderCog,
  RefreshCw,
  ShieldCheck,
} from 'lucide-react';
import { getPolicies, reloadPolicies } from '../api';
import type { PolicyInfo } from '../types';
import ConfirmDialog from '../components/ConfirmDialog';
import EmptyState from '../components/EmptyState';
import ErrorState from '../components/ErrorState';
import LoadingSkeleton from '../components/LoadingSkeleton';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';

function policyId(policy: PolicyInfo): string {
  return policy.policy_id || policy.id || 'unidentified-policy';
}

function policyName(policy: PolicyInfo): string {
  return policy.policy_name || policy.name || policyId(policy);
}

export default function Policies() {
  const [policies, setPolicies] = useState<PolicyInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showReload, setShowReload] = useState(false);
  const [reloadPaths, setReloadPaths] = useState('');
  const [reloading, setReloading] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const fetchPolicies = useCallback(async (manual = false) => {
    if (manual) setRefreshing(true);
    try {
      const data = await getPolicies();
      setPolicies(data);
      setError(null);
    } catch (fetchError) {
      setError(fetchError instanceof Error ? fetchError.message : 'Failed to load policies');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchPolicies();
  }, [fetchPolicies]);

  const parsedPaths = useMemo(
    () => reloadPaths.split('\n').map((path) => path.trim()).filter(Boolean),
    [reloadPaths],
  );

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message });
    window.setTimeout(() => setToast(null), 4000);
  };

  const handleReload = async () => {
    if (parsedPaths.length === 0) return;
    setReloading(true);
    try {
      await reloadPolicies(parsedPaths);
      showToast('success', `${parsedPaths.length} policy source${parsedPaths.length === 1 ? '' : 's'} reloaded.`);
      setShowReload(false);
      setReloadPaths('');
      await fetchPolicies();
    } catch (reloadError) {
      showToast('error', reloadError instanceof Error ? reloadError.message : 'Policy reload failed');
    } finally {
      setReloading(false);
    }
  };

  const toggleExpanded = (id: string) => {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  if (error && policies.length === 0 && !loading) {
    return <ErrorState title="Policy inventory unavailable" message={error} onRetry={() => fetchPolicies(true)} />;
  }

  return (
    <div className="page policies-page">
      <PageHeader
        eyebrow="Authorization policy"
        title="Policy Inventory"
        icon={ShieldCheck}
        subtitle="Loaded policy metadata and controlled reload workflow."
        actions={
          <div className="page-refresh">
            <StatusBadge variant={policies.length > 0 ? 'success' : 'warning'} label={`${policies.length} loaded`} />
            <button className="btn btn--secondary btn--sm" type="button" onClick={() => fetchPolicies(true)} disabled={refreshing}>
              <RefreshCw className={refreshing ? 'spin' : ''} size={14} />
              Refresh
            </button>
            <button className="btn btn--primary btn--sm" type="button" onClick={() => setShowReload(true)}>
              <FolderCog size={14} />
              Reload sources
            </button>
          </div>
        }
      />

      {toast && <div className={`toast toast--${toast.type}`} role="alert">{toast.message}</div>}
      {error && <div className="inline-notice inline-notice--warning" role="status">{error}</div>}

      <div className="policy-assurance-strip">
        <div><ShieldCheck size={17} /><span><strong>Deny-first evaluation</strong> Explicit deny remains authoritative.</span></div>
        <div><FileCode2 size={16} /><span><strong>{policies.reduce((sum, policy) => sum + (policy.rule_count || 0), 0)}</strong> declared rules reported by the gateway.</span></div>
      </div>

      {loading ? (
        <div className="policy-list"><LoadingSkeleton type="card" count={3} /></div>
      ) : policies.length === 0 ? (
        <EmptyState
          icon={FileCode2}
          title="No policy metadata returned"
          description="Load a valid TOML policy through the controlled reload action. The gateway validates every file before replacing the active policy set."
          action={<button className="btn btn--primary btn--sm" type="button" onClick={() => setShowReload(true)}>Reload policy sources</button>}
        />
      ) : (
        <div className="policy-list">
          {policies.map((policy) => {
            const id = policyId(policy);
            const isExpanded = expanded.has(id);
            const effect = policy.default_effect?.toLowerCase();
            return (
              <article className="policy-record" key={id}>
                <div className="policy-record__accent" aria-hidden="true" />
                <div className="policy-record__identity">
                  <span className="policy-record__icon"><ShieldCheck size={18} /></span>
                  <div>
                    <h3>{policyName(policy)}</h3>
                    <code>{id}</code>
                  </div>
                </div>
                <div className="policy-record__facts">
                  <div><span>Rules</span><strong>{policy.rule_count ?? 'Unavailable'}</strong></div>
                  <div>
                    <span>Default effect</span>
                    {effect ? (
                      <StatusBadge
                        variant={effect === 'deny' ? 'error' : effect === 'allow' ? 'success' : 'warning'}
                        label={effect}
                      />
                    ) : <strong className="unavailable-label">Not exposed</strong>}
                  </div>
                  <div><span>Source</span><strong>{policy.source || 'Gateway runtime'}</strong></div>
                  <div><span>Load state</span><StatusBadge variant="success" label="Loaded" /></div>
                </div>
                <button
                  className="policy-record__expand"
                  type="button"
                  onClick={() => toggleExpanded(id)}
                  aria-expanded={isExpanded}
                  aria-controls={`policy-${id}`}
                >
                  {isExpanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                  {isExpanded ? 'Hide details' : 'Inspect details'}
                </button>
                {isExpanded && (
                  <div className="policy-record__details" id={`policy-${id}`}>
                    <div className="policy-rule-visual">
                      <span className="policy-rule-visual__deny">Deny</span>
                      <span className="policy-rule-visual__approval">Approval</span>
                      <span className="policy-rule-visual__allow">Allow</span>
                    </div>
                    <div>
                      <h4>Rule inspection</h4>
                      <p>
                        The gateway reports policy identity and aggregate rule count, but does not expose individual
                        rule bodies through the current API. KAVACH does not invent or reconstruct rule definitions in
                        the browser.
                      </p>
                    </div>
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}

      <ConfirmDialog
        open={showReload}
        title="Reload policy sources"
        message="The gateway will parse and validate every path before replacing the active policy set. If validation fails, the current policy remains active."
        confirmLabel={reloading ? 'Reloading…' : `Validate & reload ${parsedPaths.length || ''}`.trim()}
        confirmVariant="primary"
        confirmDisabled={parsedPaths.length === 0 || reloading}
        onConfirm={handleReload}
        onCancel={() => { if (!reloading) { setShowReload(false); setReloadPaths(''); } }}
      >
        <div className="modal__field">
          <label htmlFor="reload-paths" className="modal__label">TOML policy paths · one per line</label>
          <textarea
            id="reload-paths"
            className="modal__textarea"
            value={reloadPaths}
            onChange={(event) => setReloadPaths(event.target.value)}
            placeholder={"./config/default-policy.toml\n./config/custom-policy.toml"}
            rows={5}
            autoComplete="off"
          />
        </div>
        {parsedPaths.length > 0 ? (
          <div className="reload-preview">
            <span><CheckCircle2 size={14} /> Sources queued for validation</span>
            {parsedPaths.map((path) => <code key={path}>{path}</code>)}
          </div>
        ) : (
          <div className="inline-notice inline-notice--warning">
            <AlertTriangle size={14} />
            Enter at least one policy source. Empty reloads are never submitted.
          </div>
        )}
      </ConfirmDialog>
    </div>
  );
}
