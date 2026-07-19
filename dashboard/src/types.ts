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
  [key: string]: unknown;
}

export interface ReadyStatus {
  ready: boolean;
  adapters?: Record<string, string>;
  audit_store?: string;
  approval_store?: string;
  policy_count?: number;
  [key: string]: unknown;
}

export interface StatusInfo {
  service: string;
  version?: string;
  bind?: string;
  uptime_seconds?: number;
  [key: string]: unknown;
}

export interface ApprovalRecord {
  approval_id: string;
  request_id: string;
  operation: string;
  resource_kind: string;
  summary: string;
  created_at: string;
  expires_at: string;
  state: string;
  matched_rule_ids?: string[];
  [key: string]: unknown;
}

export interface AuditEvent {
  sequence: number;
  event_id?: string;
  timestamp: string;
  category: string;
  request_id?: string | null;
  operation?: string;
  resource_kind?: string;
  decision?: string;
  reason_code?: string;
  summary?: string;
  agent_id?: string;
  matched_rule_ids?: string[];
  previous_hash?: string;
  current_hash?: string;
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
  kind: string;
  detail: string;
}

export interface PolicyInfo {
  policy_id: string;
  policy_name: string;
  rule_count: number;
  default_effect: string;
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
