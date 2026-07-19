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
  status?: string;
  ready?: boolean;
  adapters?: Record<string, string>;
  adapter_filesystem?: boolean;
  adapter_command?: boolean;
  adapter_network?: boolean;
  audit_available?: boolean;
  approval_available?: boolean;
  policy_loaded?: boolean;
  [key: string]: unknown;
}

export interface StatusInfo {
  service: string;
  version?: string;
  bind?: string;
  bind_address?: string;
  uptime_seconds?: number;
  uptime?: number;
  [key: string]: unknown;
}

export interface ApprovalRecord {
  approval_id?: string;
  id?: string;
  request_id: string;
  operation?: string;
  resource_kind?: string;
  resource?: string;
  summary?: string;
  created_at?: string;
  expires_at?: string;
  state?: string;
  status?: string;
  matched_rule_ids?: string[];
  actor?: string | null;
  denial_reason?: string | null;
  audit_sequence?: number | null;
  [key: string]: unknown;
}

export interface AuditEvent {
  sequence: number;
  event_id?: string;
  timestamp: string;
  category: string;
  request_id?: string | null;
  operation?: string;
  decision?: string;
  summary?: string;
  agent_id?: string | null;
  resource_kind?: string | null;
  reason_code?: string | null;
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
  error: string;
}

export interface PolicyInfo {
  policy_id?: string;
  policy_name?: string;
  id?: string;
  name?: string;
  source?: string;
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
