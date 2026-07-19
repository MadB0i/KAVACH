import { useState, type FormEvent } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { ApiError } from '../types';
import { useTheme } from '../context/useTheme';

export default function Login() {
  const [tokenInput, setTokenInput] = useState('');
  const [actorInput, setActorInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { login, isAuthenticated } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const navigate = useNavigate();

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!tokenInput.trim()) {
      setError('Please enter an authentication token');
      return;
    }
    if (!actorInput.trim()) {
      setError('Please enter your operator identifier');
      return;
    }
    setLoading(true);
    try {
      await login(tokenInput.trim(), actorInput.trim());
      navigate('/', { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Connection failed. Is the API gateway running?');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-card__header">
          <div className="login-card__logo" aria-hidden="true">K</div>
          <div className="login-card__eyebrow">SECURE OPERATOR ACCESS</div>
          <h2 className="login-card__title">KAVACH Control Plane</h2>
          <p className="login-card__subtitle">Authenticate to inspect policy decisions and the verified audit chain.</p>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="actor" className="form-label">Operator ID</label>
            <input
              id="actor"
              type="text"
              className="form-input"
              value={actorInput}
              onChange={(e) => setActorInput(e.target.value)}
              placeholder="e.g. security-operator"
              autoComplete="username"
              spellCheck={false}
              autoFocus
            />
          </div>
          <div className="form-group">
            <label htmlFor="token" className="form-label">Authentication Token</label>
            <input
              id="token"
              type="password"
              className="form-input"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="Enter your API token"
              autoComplete="off"
              spellCheck={false}
              aria-describedby={error ? 'login-error' : undefined}
            />
          </div>
          {error && (
            <p className="form-error" id="login-error" role="alert">{error}</p>
          )}
          <button
            type="submit"
            className={`btn btn--primary btn--full ${loading ? 'btn--loading' : ''}`}
            disabled={loading}
            aria-label={loading ? 'Connecting...' : 'Connect to Dashboard'}
          >
            {loading ? 'Connecting' : 'Connect'}
          </button>
        </form>
        <div style={{ marginTop: 20, textAlign: 'center' }}>
          <button
            className="btn btn--ghost btn--sm"
            onClick={toggleTheme}
            aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
          >
            {isDark ? '\u2600 Light mode' : '\u263E Dark mode'}
          </button>
        </div>
      </div>
    </div>
  );
}
