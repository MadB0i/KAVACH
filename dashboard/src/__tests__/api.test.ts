import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fetchApi, setAuthToken, clearAuthToken, getAuthToken, getHealth, getReady, getApprovals, getApproval, approveApproval, denyApproval, getAuditEvents, verifyAudit, reloadPolicies } from '../api';

function mockResponse(overrides: Partial<Response> = {}): Response {
  return {
    ok: true,
    status: 200,
    statusText: 'OK',
    headers: new Headers(),
    redirected: false,
    type: 'basic' as const,
    url: '',
    clone: () => mockResponse(overrides),
    body: null,
    bodyUsed: false,
    arrayBuffer: () => Promise.resolve(new ArrayBuffer(0)),
    blob: () => Promise.resolve(new Blob()),
    formData: () => Promise.resolve(new FormData()),
    text: () => Promise.resolve(''),
    json: () => Promise.resolve({ status: 'success', data: null }),
    ...overrides,
  } as Response;
}

const mockFetch = vi.fn();
globalThis.fetch = mockFetch;

function mockOkResponse(data: unknown): Response {
  return mockResponse({
    ok: true,
    text: () => Promise.resolve(JSON.stringify(data)),
    json: () => Promise.resolve(data),
  });
}

function mockErrorResponse(status: number, data: unknown): Response {
  return mockResponse({
    ok: false,
    status,
    text: () => Promise.resolve(JSON.stringify(data)),
    json: () => Promise.resolve(data),
  });
}

describe('API Module', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearAuthToken();
  });

  it('setAuthToken and clearAuthToken work', () => {
    expect(getAuthToken()).toBeNull();
    setAuthToken('test-token');
    expect(getAuthToken()).toBe('test-token');
    clearAuthToken();
    expect(getAuthToken()).toBeNull();
  });

  it('fetchApi adds auth headers', async () => {
    setAuthToken('my-token');
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'success', data: { key: 'value' } }));
    await fetchApi('/api/test');
    expect(mockFetch).toHaveBeenCalledWith(
      '/api/test',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer my-token',
        }),
      })
    );
  });

  it('fetchApi handles errors correctly', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'error', error: { code: 'NOT_FOUND', message: 'Resource not found' } }));
    await expect(fetchApi('/api/test')).rejects.toThrow('Resource not found');
  });

  it('fetchApi throws on HTTP errors', async () => {
    mockFetch.mockResolvedValueOnce(mockErrorResponse(500, {}));
    await expect(fetchApi('/api/test')).rejects.toThrow('HTTP 500');
  });

  it('fetchApi returns 401 error', async () => {
    setAuthToken('token');
    mockFetch.mockResolvedValueOnce(mockErrorResponse(401, {}));
    await expect(fetchApi('/api/test')).rejects.toThrow('Authentication failed');
    expect(getAuthToken()).toBeNull();
  });

  it('getHealth calls correct endpoint', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'success', data: { status: 'ok' } }));
    await getHealth();
    expect(mockFetch).toHaveBeenCalledWith('/health', expect.any(Object));
  });

  it('getReady calls correct endpoint', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'success', data: { ready: true } }));
    await getReady();
    expect(mockFetch).toHaveBeenCalledWith('/ready', expect.any(Object));
  });

  it('getApprovals calls correct endpoint', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'success', data: [] }));
    await getApprovals();
    expect(mockFetch).toHaveBeenCalledWith('/api/approvals', expect.any(Object));
  });

  it('approveApproval sends correct body', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'success', data: { success: true } }));
    await approveApproval('abc-123', 'admin');
    expect(mockFetch).toHaveBeenCalledWith(
      '/api/approvals/abc-123/approve',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ actor: 'admin' }),
      })
    );
  });

  it('denyApproval sends reason when provided', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'success', data: { success: true } }));
    await denyApproval('abc-123', 'admin', 'Not authorized');
    expect(mockFetch).toHaveBeenCalledWith(
      '/api/approvals/abc-123/deny',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ actor: 'admin', reason: 'Not authorized' }),
      })
    );
  });

  it('getAuditEvents builds query params', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'success', data: [] }));
    await getAuditEvents({ after: 10, limit: 50, category: 'allow', request_id: 'req-1' });
    const callUrl = mockFetch.mock.calls[0]![0]! as string;
    expect(callUrl).toContain('after=10');
    expect(callUrl).toContain('limit=50');
    expect(callUrl).toContain('category=allow');
    expect(callUrl).toContain('request_id=req-1');
  });

  it('verifyAudit sends POST', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'success', data: { chain_valid: true } }));
    await verifyAudit();
    expect(mockFetch).toHaveBeenCalledWith(
      '/api/audit/verify',
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('reloadPolicies sends policy_paths', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'success', data: { success: true } }));
    await reloadPolicies(['/path/to/policy.yaml']);
    expect(mockFetch).toHaveBeenCalledWith(
      '/api/policies/reload',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ policy_paths: ['/path/to/policy.yaml'] }),
      })
    );
  });

  it('getApproval calls correct endpoint', async () => {
    mockFetch.mockResolvedValueOnce(mockOkResponse({ status: 'success', data: { id: 'abc' } }));
    await getApproval('abc-123');
    expect(mockFetch).toHaveBeenCalledWith('/api/approvals/abc-123', expect.any(Object));
  });
});
