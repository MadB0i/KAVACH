import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/useAuth';
import { ApiError } from '../types';
import { useTheme } from '../context/useTheme';

export default function Login() {
  const [tokenInput, setTokenInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { login, isAuthenticated } = useAuth();
  const { isDark, toggleTheme } = useTheme();
  const navigate = useNavigate();

  if (isAuthenticated) {
    navigate('/', { replace: true });
    return null;
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!tokenInput.trim()) {
      setError('Please enter an authentication token');
      return;
    }
    setLoading(true);
    try {
      await login(tokenInput.trim());
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
          <div className="login-card__logo">K</div>
          <h2 className="login-card__title">KAVACH Dashboard</h2>
          <p className="login-card__subtitle">Zero-Trust Runtime</p>
        </div>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="token" className="form-label">Authentication Token</label>
            <input
              id="token"
              type="password"
              className="form-input"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="Enter your API token"
              autoFocus
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
