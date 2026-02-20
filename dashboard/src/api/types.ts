import type { ServiceName } from "@/lib/constants";

// --- Status ---
export type ProxyStatus = "running" | "stopped" | "error";

export interface StatusResponse {
  proxy: ProxyStatus;
  uptime_secs: number;
  version: string;
  active_credentials: number;
  total_requests_24h: number;
  blocked_requests_24h: number;
  warnings: Warning[];
}

export interface Warning {
  id: string;
  level: "info" | "warning" | "critical";
  message: string;
  timestamp: string;
  /** If the warning is ongoing vs one-time */
  ongoing?: boolean;
}

// --- Spend ---
export interface SpendBucket {
  service: ServiceName;
  spent_cents: number;
  budget_cents: number;
  request_count: number;
}

export interface SpendResponse {
  period: "24h" | "7d" | "30d";
  total_spent_cents: number;
  total_budget_cents: number;
  buckets: SpendBucket[];
}

// --- Recent Activity (for dashboard) ---
export interface RecentActivity {
  id: string;
  timestamp: string;
  service: ServiceName;
  method: string;
  endpoint: string;
  action: "allow" | "deny";
  cost_cents: number;
  deny_reason?: string;
}

export interface RecentActivityResponse {
  activities: RecentActivity[];
}

// --- Auth ---
export interface AuthStatusResponse {
  initialized: boolean;
  authenticated: boolean;
}

export interface LoginResponse {
  token: string;
  expires_at: string;
}

export interface SetupResponse {
  success: boolean;
  message: string;
}

export interface LogoutResponse {
  success: boolean;
}

export interface AuthErrorResponse {
  error: string;
  retry_after_seconds?: number;
}

// --- Alerts ---
export type AlertType =
  | "prompt_drift"
  | "prompt_size"
  | "budget_warning"
  | "budget_exceeded"
  | "onchain_denied"
  | "rate_limit_hit";

export type AlertSeverity = "critical" | "warning";

export interface Alert {
  id: string;
  type: AlertType;
  severity: AlertSeverity;
  service: string;
  message: string;
  /** Unix timestamp in seconds */
  timestamp: number;
  dismissed: boolean;
}

export interface AlertsResponse {
  alerts: Alert[];
}

export interface DismissAlertResponse {
  success: boolean;
}

// --- Generic ---
export interface ApiError {
  error: string;
  code: number;
}
