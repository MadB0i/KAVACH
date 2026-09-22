import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import AuditTimeline from '../pages/AuditTimeline';
import * as api from '../api';
import { AuthProvider } from '../context/AuthContext';

vi.mock('../api', () => ({
  getAuditEvents: vi.fn(),
  verifyAudit: vi.fn(),
  setAuthToken: vi.fn(),
  clearAuthToken: vi.fn(),
  getStatus: vi.fn(),
  getApiBase: vi.fn(() => 'http://localhost:7421'),
}));

function renderWithProviders(ui: React.ReactElement) {
  return render(
    <MemoryRouter>
      <AuthProvider>{ui}</AuthProvider>
    </MemoryRouter>
  );
}

const mockEvents = [
  { sequence: 1, timestamp: '2025-01-01T00:00:00Z', category: 'allow', request_id: 'req-1', operation: 'read', decision: 'allow', summary: 'Read allowed' },
  { sequence: 2, timestamp: '2025-01-01T00:01:00Z', category: 'deny', request_id: 'req-2', operation: 'write', decision: 'deny', summary: 'Write denied' },
];

describe('AuditTimeline', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getStatus).mockResolvedValue({ service: 'kavach' });
    vi.mocked(api.verifyAudit).mockResolvedValue({ chain_valid: true, event_count: 2, verified_to: 2 });
  });

  it('renders audit events', async () => {
    vi.mocked(api.getAuditEvents).mockResolvedValue(mockEvents);
    renderWithProviders(<AuditTimeline />);
    await waitFor(() => {
      expect(screen.getByText('#1')).toBeInTheDocument();
      expect(screen.getByText('#2')).toBeInTheDocument();
    });
  });

  it('shows empty state when no events', async () => {
    vi.mocked(api.getAuditEvents).mockResolvedValue([]);
    renderWithProviders(<AuditTimeline />);
    await waitFor(() => {
      expect(screen.getByText('No audit events recorded')).toBeInTheDocument();
    });
  });

  it('handles error state', async () => {
    vi.mocked(api.getAuditEvents).mockRejectedValue(new Error('API error'));
    renderWithProviders(<AuditTimeline />);
    await waitFor(() => {
      expect(screen.getByText('Audit timeline unavailable')).toBeInTheDocument();
    });
  });
});
