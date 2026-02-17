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

// --- Generic ---
export interface ApiError {
  error: string;
  code: number;
}
