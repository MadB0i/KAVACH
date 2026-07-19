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

  const response = await fetch(url, { ...options, headers });

  if (!response.ok) {
    if (response.status === 401) {
      clearAuthToken();
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
  const json = JSON.parse(text) as ApiResponse<T> | T;
  if (
    typeof json === 'object'
    && json !== null
    && 'status' in json
    && ((json as ApiResponse<T>).status === 'success' || (json as ApiResponse<T>).status === 'error')
    && ('data' in json || 'error' in json)
  ) {
    const envelope = json as ApiResponse<T>;
    if (envelope.status === 'error' && envelope.error) {
      throw new ApiError(envelope.error.code, envelope.error.message, envelope.request_id);
    }
    return envelope.data as T;
  }
  return json as T;
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

export function approveApproval(id: string, actor: string): Promise<{ success: boolean }> {
  return fetchApi<{ success: boolean }>(`/api/approvals/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
    body: JSON.stringify({ actor }),
  });
}

export function denyApproval(id: string, actor: string, reason?: string): Promise<{ success: boolean }> {
  const body: Record<string, string> = { actor };
  if (reason) body.reason = reason;
  return fetchApi<{ success: boolean }>(`/api/approvals/${encodeURIComponent(id)}/deny`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export interface AuditEventParams {
  after?: number;
  limit?: number;
  category?: string;
  request_id?: string;
}

export function getAuditEvents(params?: AuditEventParams): Promise<AuditEvent[]> {
  const search = new URLSearchParams();
  if (params?.after !== undefined) search.set('after', String(params.after));
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
