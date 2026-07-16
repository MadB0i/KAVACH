import { useState, useCallback } from 'react';
import { verifyAudit } from '../api';
import type { AuditVerifyResult } from '../types';
import PageHeader from '../components/PageHeader';
import SectionCard from '../components/SectionCard';
import DataTable from '../components/DataTable';
import EmptyState from '../components/EmptyState';
import LoadingState from '../components/LoadingState';
import ErrorState from '../components/ErrorState';
import StatusBadge from '../components/StatusBadge';

export default function AuditVerification() {
  const [result, setResult] = useState<AuditVerifyResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasRun, setHasRun] = useState(false);
  const [verifyTime, setVerifyTime] = useState<string | null>(null);
  const [verifyDuration, setVerifyDuration] = useState<number | null>(null);

  const runVerification = useCallback(async () => {
    setLoading(true);
    setError(null);
    const start = Date.now();
    try {
      const data = await verifyAudit();
      setResult(data);
      setHasRun(true);
      setVerifyTime(new Date().toLocaleTimeString());
      setVerifyDuration(Date.now() - start);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setLoading(false);
    }
  }, []);

  if (!hasRun && !loading && !error) {
    return (
      <div className="page">
        <PageHeader
          title="Audit Chain Verification"
          subtitle="Verify the cryptographic integrity of the audit event chain"
        />
        <div className="empty-state" style={{ padding: '64px 20px' }}>
          <div className="empty-state__icon">{'\u2713'}</div>
          <h3 className="empty-state__title">Ready to Verify</h3>
          <p className="empty-state__description">
            Run a verification to check that the audit chain has not been tampered with.
          </p>
          <button
            className="btn btn--primary"
            onClick={runVerification}
            disabled={loading}
            style={{ marginTop: 12 }}
            aria-label="Run verification"
          >
            {loading ? 'Verifying...' : 'Run Verification'}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <PageHeader
        title="Audit Chain Verification"
        subtitle="Verify the cryptographic integrity of the audit event chain"
        actions={
          <button
            className={`btn btn--primary ${loading ? 'btn--loading' : ''}`}
            onClick={runVerification}
            disabled={loading}
            aria-label="Re-verify"
          >
            {loading ? 'Verifying' : 'Re-verify'}
          </button>
        }
      />

      {loading && !result && <LoadingState message="Verifying audit chain..." />}

      {error && <ErrorState title="Verification Failed" message={error} onRetry={runVerification} />}

      {result && !loading && (
        <>
          <div className="verify-summary">
            <div className="verify-summary__status">
              <StatusBadge
                variant={result.chain_valid ? 'success' : 'error'}
                label={result.chain_valid ? 'Chain Valid' : 'Chain Tampered'}
              />
            </div>
            <div className="verify-summary__stats">
              <div className="verify-summary__stat">
                <span className="verify-summary__stat-label">Events</span>
                <span className="verify-summary__stat-value">{result.event_count ?? '\u2014'}</span>
              </div>
              <div className="verify-summary__stat">
                <span className="verify-summary__stat-label">Verified Range</span>
                <span className="verify-summary__stat-value">
                  {result.verified_to !== undefined ? `1 \u2013 ${result.verified_to}` : '\u2014'}
                </span>
              </div>
              <div className="verify-summary__stat">
                <span className="verify-summary__stat-label">Last Verification</span>
                <span className="verify-summary__stat-value">{verifyTime || '\u2014'}</span>
              </div>
              <div className="verify-summary__stat">
                <span className="verify-summary__stat-label">Duration</span>
                <span className="verify-summary__stat-value">
                  {verifyDuration !== null ? `${verifyDuration}ms` : '\u2014'}
                </span>
              </div>
            </div>
          </div>

          <SectionCard title={`Verification Errors (${result.errors?.length || 0})`}>
            {!result.errors || result.errors.length === 0 ? (
              <EmptyState
                icon={'\u2713'}
                title="No Integrity Errors"
                description="The audit chain is fully valid with no tampering detected."
              />
            ) : (
              <DataTable
                columns={[
                  { key: 'sequence', header: 'Sequence', className: 'cell-mono', render: (err) => `#${err.sequence}` },
                  { key: 'error', header: 'Error', className: 'cell-mono', render: (err) => err.error },
                ]}
                data={result.errors}
                keyField={(err) => err.sequence}
                compact
              />
            )}
          </SectionCard>
        </>
      )}
    </div>
  );
}
