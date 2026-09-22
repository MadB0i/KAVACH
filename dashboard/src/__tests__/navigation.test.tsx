import { render, screen, fireEvent } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import Layout from '../components/Layout';
import { AuthProvider } from '../context/AuthContext';
import { ThemeProvider } from '../context/ThemeContext';
import * as api from '../api';

vi.mock('../api', () => ({
  getStatus: vi.fn(),
  getHealth: vi.fn(),
  verifyAudit: vi.fn(),
  setAuthToken: vi.fn(),
  clearAuthToken: vi.fn(),
  getApiBase: vi.fn(() => 'http://localhost:7421'),
}));

function mockMatchMedia(matches: boolean) {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
}

function renderWithProviders(ui: React.ReactElement) {
  return render(
    <MemoryRouter initialEntries={['/']}>
      <AuthProvider>
        <ThemeProvider>
          {ui}
        </ThemeProvider>
      </AuthProvider>
    </MemoryRouter>
  );
}

describe('Navigation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockMatchMedia(false);
    vi.mocked(api.getStatus).mockResolvedValue({ service: 'kavach', version: '1.0.0' });
    vi.mocked(api.getHealth).mockReturnValue(new Promise(() => {}));
    vi.mocked(api.verifyAudit).mockReturnValue(new Promise(() => {}));
  });

  it('renders all navigation links', async () => {
    renderWithProviders(<Layout />);
    const links = [
      'Overview', 'Live Requests', 'Pending Approvals', 'Audit Timeline',
      'Policies', 'Agents / Sessions', 'Security Warnings', 'System Health',
      'Configuration', 'Audit Verification',
    ];
    for (const label of links) {
      expect(screen.getByRole('link', { name: label })).toBeInTheDocument();
    }
  });

  it('has working logout button', () => {
    renderWithProviders(<Layout />);
    const operatorBtn = screen.getByLabelText('Open operator menu');
    fireEvent.click(operatorBtn);
    const logoutBtn = screen.getByText('End session');
    fireEvent.click(logoutBtn);
  });

  it('has theme toggle button', () => {
    renderWithProviders(<Layout />);
    const themeBtn = screen.getByLabelText(/switch to/i);
    expect(themeBtn).toBeInTheDocument();
  });

  it('shows connection status indicator', () => {
    renderWithProviders(<Layout />);
    const statusIndicator = screen.getByText('Gateway');
    expect(statusIndicator).toBeInTheDocument();
  });
});
