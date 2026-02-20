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

// --- Alert Query Params ---
export interface AlertsQueryParams {
  type?: AlertType;
  dismissed?: boolean;
  limit?: number;
  skip?: number;
}

// --- Alert Config ---
export interface AlertConfigToggles {
  prompt_drift: boolean;
  prompt_size: boolean;
  budget_warning: boolean;
  budget_exceeded: boolean;
  onchain_denied: boolean;
  rate_limit_hit: boolean;
}

export interface AlertConfigResponse {
  toggles: AlertConfigToggles;
  retention_days: number;
}

export interface AlertConfigUpdatePayload {
  prompt_drift?: boolean;
  prompt_size?: boolean;
  budget_warning?: boolean;
  budget_exceeded?: boolean;
  onchain_denied?: boolean;
  rate_limit_hit?: boolean;
  retention_days?: number;
}

export interface AlertConfigUpdateResponse {
  success: boolean;
  toggles: AlertConfigToggles;
  retention_days: number;
}

// --- Spend Analytics ---
export interface DailySpendEntry {
  date: string;
  service: ServiceName;
  cost_usd: number;
  request_count: number;
}

export interface ServiceBudget {
  daily_limit: number | null;
  spent_today: number;
  warning_active?: boolean;
  warning_pct?: number;
}

export interface SpendConfig {
  track_spend: boolean;
  spend_history_days: number;
}

export interface SpendAnalyticsResponse {
  enabled: boolean;
  daily: DailySpendEntry[];
  budgets: Record<string, ServiceBudget>;
  config: SpendConfig;
}

// --- Generic ---
export interface ApiError {
  error: string;
  code: number;
}
