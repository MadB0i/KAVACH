import { useState, useCallback } from 'react';
import { verifyAudit } from '../api';
import type { AuditVerifyResult } from '../types';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import EmptyState from '../components/EmptyState';
import StatusBadge from '../components/StatusBadge';

export default function AuditVerification() {
  const [result, setResult] = useState<AuditVerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasRun, setHasRun] = useState(false);

  const runVerification = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await verifyAudit();
      setResult(data);
      setHasRun(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setLoading(false);
    }
  }, []);

  if (!hasRun && !loading && !error) {
    return (
      <div className="page">
        <h2 className="page__title">Audit Chain Verification</h2>
        <p className="page__subtitle">Verify the integrity of the audit event chain</p>
        <button className="btn btn--primary" onClick={runVerification} aria-label="Run verification">
          Run Verification
        </button>
      </div>
    );
  }

  if (loading) return <LoadingState message="Verifying audit chain..." />;
  if (error) return <ErrorState title="Verification failed" message={error} onRetry={runVerification} />;

  const errors = result?.errors || [];

  return (
    <div className="page">
      <div className="page__header">
        <h2 className="page__title">Audit Chain Verification</h2>
        <button className="btn btn--primary" onClick={runVerification} aria-label="Re-verify">
          Re-verify
        </button>
      </div>

      {result && (
        <div className="verify-result">
          <div className="verify-result__summary">
            <StatusBadge
              variant={result.chain_valid ? 'success' : 'error'}
              label={result.chain_valid ? 'Chain is Valid' : 'Chain Integrity Error'}
            />
          </div>
          <div className="verify-result__stats">
            <p><strong>Event Count:</strong> {result.event_count ?? '?'}</p>
            <p><strong>Verified To:</strong> {result.verified_to !== undefined ? `#${result.verified_to}` : '?'}</p>
          </div>
        </div>
      )}

      {errors.length === 0 ? (
        <EmptyState icon={'\u2713'} title="No Errors" description="The audit chain is fully valid with no integrity errors." />
      ) : (
        <div className="section">
          <h3 className="section__title">Verification Errors ({errors.length})</h3>
          <div className="table-container">
            <table className="table" role="table">
              <thead>
                <tr>
                  <th>Sequence</th>
                  <th>Error</th>
                </tr>
              </thead>
              <tbody>
                {errors.map((err, idx) => (
                  <tr key={idx}>
                    <td className="cell-mono">#{err.sequence}</td>
                    <td className="cell-error">{err.error}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
