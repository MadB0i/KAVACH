import { useState, type FormEvent } from 'react';
import { ArrowRight, CheckCircle2, KeyRound, LockKeyhole, Moon, ShieldCheck, Sun } from 'lucide-react';
import { Navigate, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { useTheme } from '../context/useTheme';
import { ApiError } from '../types';

export default function Login() {
  const [tokenInput, setTokenInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { login, isAuthenticated } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const navigate = useNavigate();

  if (isAuthenticated) return <Navigate to="/" replace />;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    const token = tokenInput.trim();
    if (!token) {
      setError('Enter the gateway authentication token.');
      return;
    }
    if (!/^[0-9a-fA-F]{64}$/.test(token)) {
      setError('The gateway token must be exactly 64 hexadecimal characters.');
      return;
    }
    setLoading(true);
    try {
      await login(token);
      setTokenInput('');
      navigate('/', { replace: true });
    } catch (loginError) {
      setError(loginError instanceof ApiError
        ? loginError.message
        : 'The gateway could not be reached. Confirm that the local KAVACH service is running.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="login-page">
      <button
        className="login-theme-toggle"
        type="button"
        onClick={toggleTheme}
        aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
      >
        {isDark ? <Sun size={17} /> : <Moon size={17} />}
      </button>

      <section className="login-story" aria-label="KAVACH security principles">
        <div className="login-story__brand">
          <span><ShieldCheck size={25} strokeWidth={1.7} /></span>
          <div><strong>KAVACH</strong><small>Zero-Trust Runtime</small></div>
        </div>
        <div className="login-story__content">
          <span className="login-story__eyebrow">Local security control plane</span>
          <h1>Every tool call earns its authority.</h1>
          <p>
            Observe policy decisions, approval gates, enforcement outcomes, and the
            tamper-evident audit chain from one focused console.
          </p>
          <div className="login-story__principles">
            <span><CheckCircle2 size={15} />Default deny</span>
            <span><CheckCircle2 size={15} />Request-bound permits</span>
            <span><CheckCircle2 size={15} />Verifiable evidence</span>
          </div>
        </div>
        <div className="login-story__signal" aria-hidden="true">
          <div><span>01</span><strong>Policy</strong></div>
          <i />
          <div><span>02</span><strong>Enforce</strong></div>
          <i />
          <div><span>03</span><strong>Audit</strong></div>
        </div>
      </section>

      <section className="login-panel">
        <div className="login-card">
          <div className="login-card__security-mark"><LockKeyhole size={21} /></div>
          <div className="login-card__header">
            <span className="login-card__eyebrow">Operator authentication</span>
            <h2 className="login-card__title">Connect to KAVACH</h2>
            <p className="login-card__subtitle">Authenticate directly with the local gateway.</p>
          </div>
          <form onSubmit={handleSubmit} noValidate>
            <div className="form-group">
              <label htmlFor="token" className="form-label">Gateway token</label>
              <div className="secure-input">
                <KeyRound size={16} aria-hidden="true" />
                <input
                  id="token"
                  type="password"
                  value={tokenInput}
                  onChange={(event) => setTokenInput(event.target.value)}
                  placeholder="Enter authentication token"
                  autoFocus
                  autoComplete="off"
                  minLength={64}
                  maxLength={64}
                  pattern="[0-9a-fA-F]{64}"
                  spellCheck={false}
                  aria-describedby={`token-security-note${error ? ' login-error' : ''}`}
                />
              </div>
            </div>
            {error && <p className="form-error" id="login-error" role="alert">{error}</p>}
            <button
              type="submit"
              className={`btn btn--primary btn--full login-submit ${loading ? 'btn--loading' : ''}`}
              disabled={loading}
              aria-label={loading ? 'Connecting to gateway' : 'Connect to dashboard'}
            >
              <span>{loading ? 'Connecting' : 'Establish secure session'}</span>
              {!loading && <ArrowRight size={15} />}
            </button>
          </form>
          <div className="login-card__note" id="token-security-note">
            <ShieldCheck size={15} />
            <span>
              <strong>Memory-only session.</strong> The token is never written to browser storage
              and must be entered again after refresh.
            </span>
          </div>
        </div>
        <p className="login-panel__footer">KAVACH Console · Local gateway · No cloud dependency</p>
      </section>
    </main>
  );
}
