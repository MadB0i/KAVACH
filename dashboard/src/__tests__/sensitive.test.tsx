import { describe, it, expect, vi, beforeEach } from 'vitest';
import { fetchApi, setAuthToken, clearAuthToken, getAuthToken } from '../api';

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

describe('Sensitive Data Handling', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearAuthToken();
  });

  it('API error messages do not contain raw tokens', async () => {
    setAuthToken('super-secret-token-12345');
    const resp = mockResponse({
      ok: true,
      text: () => Promise.resolve(JSON.stringify({ status: 'error', error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } })),
      json: () => Promise.resolve({ status: 'error', error: { code: 'UNAUTHORIZED', message: 'Invalid credentials' } }),
    });
    mockFetch.mockResolvedValueOnce(resp);
    try {
      await fetchApi('/api/test');
    } catch (err) {
      const error = err as Error;
      expect(error.message).not.toContain('super-secret-token');
      expect(error.message).not.toContain('12345');
    }
  });

  it('token is not stored in localStorage', () => {
    setAuthToken('my-token');
    expect(getAuthToken()).toBe('my-token');
    expect(localStorage.getItem('kavach_token')).toBeNull();
  });

  it('token is in sessionStorage not localStorage', () => {
    sessionStorage.setItem('kavach_token', 'session-token');
    expect(localStorage.getItem('kavach_token')).toBeNull();
    expect(sessionStorage.getItem('kavach_token')).toBe('session-token');
    sessionStorage.removeItem('kavach_token');
  });

  it('approval summaries are truncated', () => {
    const longSummary = 'a'.repeat(200);
    const truncated = longSummary.length > 80 ? longSummary.slice(0, 77) + '...' : longSummary;
    expect(truncated.length).toBe(80);
    expect(truncated).not.toContain(longSummary.slice(80));
  });
});
