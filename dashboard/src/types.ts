export interface ApiResponse<T> {
  status: 'success' | 'error';
  data?: T;
  error?: ApiErrorData;
  request_id?: string;
}

export interface ApiErrorData {
  code: string;
  message: string;
}

export class ApiError extends Error {
  code: string;
  requestId?: string;

  constructor(code: string, message: string, requestId?: string) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.requestId = requestId;
  }
}

export interface HealthStatus {
  status: string;
  database?: string;
  policy_engine?: string;
  audit_store?: string;
  approval_store?: string;
  [key: string]: unknown;
}

export interface ReadyStatus {
  ready: boolean;
  adapters?: Record<string, string>;
  [key: string]: unknown;
}

export interface StatusInfo {
  service: string;
  version?: string;
  bind_address?: string;
  uptime?: number;
  [key: string]: unknown;
}

export interface ApprovalRecord {
  id: string;
  request_id: string;
  operation?: string;
  resource?: string;
  summary?: string;
  created_at?: string;
  expires_at?: string;
  status?: string;
  [key: string]: unknown;
}

export interface AuditEvent {
  sequence: number;
  timestamp: string;
  category: string;
  request_id: string;
  operation?: string;
  decision?: string;
  summary?: string;
  agent_id?: string;
  details?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface AuditVerifyResult {
  chain_valid: boolean;
  event_count?: number;
  verified_to?: number;
  errors?: AuditVerifyError[];
  [key: string]: unknown;
}

export interface AuditVerifyError {
  sequence: number;
  error: string;
}

export interface PolicyInfo {
  id: string;
  name: string;
  rule_count?: number;
  default_effect?: string;
  [key: string]: unknown;
}

export interface ToolRequest {
  id: string;
  operation?: string;
  resource?: string;
  summary?: string;
  timestamp?: string;
  decision?: string;
}
