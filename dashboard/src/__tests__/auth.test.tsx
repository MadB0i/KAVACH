import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthProvider } from '../context/AuthContext';
import { useAuth } from '../context/useAuth';
import { getStatus } from '../api';

vi.mock('../api', () => ({
  getStatus: vi.fn(),
  setAuthToken: vi.fn(),
  clearAuthToken: vi.fn(),
  getApiBase: vi.fn(() => ''),
}));

function TestLogin() {
  const { login, isAuthenticated, logout } = useAuth();
  if (isAuthenticated) return <div data-testid="authenticated"><button data-testid="logout-btn" onClick={logout}>Logout</button></div>;
  return (
    <div>
      <button data-testid="login-btn" onClick={() => login('test-token')}>Login</button>
      <div data-testid="not-authenticated">Not authenticated</div>
    </div>
  );
}

describe('Auth Flow', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    sessionStorage.clear();
    localStorage.clear();
  });

  it('shows not authenticated when no token', async () => {
    vi.mocked(getStatus).mockRejectedValue(new Error('No token'));
    render(
      <MemoryRouter initialEntries={['/']}>
        <AuthProvider>
          <TestLogin />
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByTestId('not-authenticated')).toBeInTheDocument();
    });
  });

  it('login succeeds with valid token', async () => {
    vi.mocked(getStatus).mockResolvedValue({ service: 'kavach', version: '1.0.0' });
    render(
      <MemoryRouter>
        <AuthProvider>
          <TestLogin />
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByTestId('not-authenticated')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('login-btn'));
    await waitFor(() => {
      expect(screen.getByTestId('authenticated')).toBeInTheDocument();
    });
  });

  it('logout clears auth state', async () => {
    vi.mocked(getStatus).mockResolvedValue({ service: 'kavach', version: '1.0.0' });
    render(
      <MemoryRouter>
        <AuthProvider>
          <TestLogin />
        </AuthProvider>
      </MemoryRouter>
    );
    await waitFor(() => {
      expect(screen.getByTestId('not-authenticated')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('login-btn'));
    await waitFor(() => {
      expect(screen.getByTestId('authenticated')).toBeInTheDocument();
    });
    fireEvent.click(screen.getByTestId('logout-btn'));
    await waitFor(() => {
      expect(screen.getByTestId('not-authenticated')).toBeInTheDocument();
    });
  });
});
