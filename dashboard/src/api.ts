import { ApiError, type ApiResponse, type HealthStatus, type ReadyStatus, type StatusInfo, type ApprovalRecord, type AuditEvent, type AuditVerifyResult, type PolicyInfo } from './types';

let authToken: string | null = null;

export function setAuthToken(token: string | null): void {
  authToken = token;
}

export function clearAuthToken(): void {
  authToken = null;
}

export function getAuthToken(): string | null {
  return authToken;
}

export function getApiBase(): string {
  if (import.meta.env.PROD) {
    return window.location.origin;
  }
  return '';
}

function getAuthHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }
  return headers;
}

export async function fetchApi<T>(path: string, options: RequestInit = {}): Promise<T> {
  const base = getApiBase();
  const url = `${base}${path}`;
  const headers = { ...getAuthHeaders(), ...(options.headers as Record<string, string> || {}) };

  let response: Response;
  try {
    response = await fetch(url, { ...options, headers });
  } catch {
    throw new ApiError('CONNECTION_FAILED', 'Connection to the KAVACH gateway failed.');
  }

  if (!response.ok) {
    if (response.status === 401) {
      clearAuthToken();
      window.dispatchEvent(new Event('kavach:unauthorized'));
      throw new ApiError('UNAUTHORIZED', 'Authentication failed. Please log in again.');
    }
    let errorData: ApiResponse<never>;
    try {
      errorData = await response.json() as ApiResponse<never>;
    } catch {
      throw new ApiError('HTTP_ERROR', `HTTP ${response.status}: ${response.statusText}`);
    }
    if (errorData.status === 'error' && errorData.error) {
      throw new ApiError(errorData.error.code, errorData.error.message, errorData.request_id);
    }
    throw new ApiError('HTTP_ERROR', `HTTP ${response.status}: ${response.statusText}`);
  }

  const text = await response.text();
  if (!text) {
    return undefined as T;
  }
  let json: ApiResponse<T>;
  try {
    json = JSON.parse(text) as ApiResponse<T>;
  } catch {
    throw new ApiError('INVALID_RESPONSE', 'The gateway returned an invalid response.');
  }
  if (json.status === 'error' && json.error) {
    throw new ApiError(json.error.code, json.error.message, json.request_id);
  }
  return json.data as T;
}

export function getHealth(): Promise<HealthStatus> {
  return fetchApi<HealthStatus>('/health');
}

export function getReady(): Promise<ReadyStatus> {
  return fetchApi<ReadyStatus>('/ready');
}

export function getStatus(): Promise<StatusInfo> {
  return fetchApi<StatusInfo>('/api/status');
}

export function getApprovals(): Promise<ApprovalRecord[]> {
  return fetchApi<ApprovalRecord[]>('/api/approvals');
}

export function getApproval(id: string): Promise<ApprovalRecord> {
  return fetchApi<ApprovalRecord>(`/api/approvals/${encodeURIComponent(id)}`);
}

export function approveApproval(id: string, actor: string): Promise<{ approval_id: string; outcome: string }> {
  return fetchApi<{ approval_id: string; outcome: string }>(`/api/approvals/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
    body: JSON.stringify({ actor }),
  });
}

export function denyApproval(id: string, actor: string, reason?: string): Promise<{ approval_id: string; outcome: string }> {
  const body: Record<string, string> = { actor };
  if (reason) body.reason = reason;
  return fetchApi<{ approval_id: string; outcome: string }>(`/api/approvals/${encodeURIComponent(id)}/deny`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export interface AuditEventParams {
  after?: number;
  before?: number;
  limit?: number;
  category?: string;
  request_id?: string;
}

export function getAuditEvents(params?: AuditEventParams): Promise<AuditEvent[]> {
  const search = new URLSearchParams();
  if (params?.after !== undefined) search.set('after', String(params.after));
  if (params?.before !== undefined) search.set('before', String(params.before));
  if (params?.limit !== undefined) search.set('limit', String(params.limit));
  if (params?.category) search.set('category', params.category);
  if (params?.request_id) search.set('request_id', params.request_id);
  const qs = search.toString();
  return fetchApi<AuditEvent[]>(`/api/audit/events${qs ? `?${qs}` : ''}`);
}

export function verifyAudit(): Promise<AuditVerifyResult> {
  return fetchApi<AuditVerifyResult>('/api/audit/verify', { method: 'POST' });
}

export function getPolicies(): Promise<PolicyInfo[]> {
  return fetchApi<PolicyInfo[]>('/api/policies');
}

export function reloadPolicies(policyPaths: string[]): Promise<{ success: boolean }> {
  return fetchApi<{ success: boolean }>('/api/policies/reload', {
    method: 'POST',
    body: JSON.stringify({ policy_paths: policyPaths }),
  });
}
