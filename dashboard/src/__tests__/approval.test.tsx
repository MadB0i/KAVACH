import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import PendingApprovals from '../pages/PendingApprovals';
import * as api from '../api';
import { AuthProvider } from '../context/AuthContext';

vi.mock('../api', () => ({
  getApprovals: vi.fn(),
  approveApproval: vi.fn(),
  denyApproval: vi.fn(),
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

const mockApprovals = [
  { id: 'approval-1', request_id: 'req-1', operation: 'read', resource: '/data', summary: 'Read access to /data', created_at: '2025-01-01T00:00:00Z', expires_at: '2025-01-02T00:00:00Z' },
  { id: 'approval-2', request_id: 'req-2', operation: 'write', resource: '/config', summary: 'Write access to configuration', created_at: '2025-01-01T01:00:00Z', expires_at: '2025-01-02T01:00:00Z' },
];

describe('PendingApprovals', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.getStatus).mockResolvedValue({ service: 'kavach' });
  });

  it('renders empty state when no approvals', async () => {
    vi.mocked(api.getApprovals).mockResolvedValue([]);
    renderWithProviders(<PendingApprovals />);
    await waitFor(() => {
      expect(screen.getByText('Approval queue clear')).toBeInTheDocument();
    });
  });

  it('renders approval records', async () => {
    vi.mocked(api.getApprovals).mockResolvedValue(mockApprovals);
    renderWithProviders(<PendingApprovals />);
    await waitFor(() => {
      expect(screen.getByText('read')).toBeInTheDocument();
      expect(screen.getByText('write')).toBeInTheDocument();
    });
  });

  it('approve action calls correct API', async () => {
    vi.mocked(api.getApprovals).mockResolvedValue(mockApprovals);
    vi.mocked(api.approveApproval).mockResolvedValue({ success: true });
    renderWithProviders(<PendingApprovals />);
    await waitFor(() => {
      expect(screen.getByText('read')).toBeInTheDocument();
    });
    const approveButtons = screen.getAllByText('Approve');
    const tableApproveBtn = approveButtons[0]!;
    fireEvent.click(tableApproveBtn);
    await waitFor(() => {
      expect(screen.getByText(/mark this approval as granted/i)).toBeInTheDocument();
    });
    const dialogApproveBtn = screen.getByRole('button', { name: 'Approve request' });
    fireEvent.click(dialogApproveBtn);
    await waitFor(() => {
      expect(api.approveApproval).toHaveBeenCalled();
    });
  });

  it('deny shows confirm dialog with reason', async () => {
    vi.mocked(api.getApprovals).mockResolvedValue(mockApprovals);
    vi.mocked(api.denyApproval).mockResolvedValue({ success: true });
    renderWithProviders(<PendingApprovals />);
    await waitFor(() => {
      expect(screen.getByText('read')).toBeInTheDocument();
    });
    const denyButtons = screen.getAllByText('Deny');
    fireEvent.click(denyButtons[0]!);
    await waitFor(() => {
      expect(screen.getByText(/pending request will be rejected/i)).toBeInTheDocument();
      const denyBtn = screen.getByRole('button', { name: 'Deny request' });
      expect(denyBtn).toBeInTheDocument();
    });
  });
});
