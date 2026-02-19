import type {
  StatusResponse,
  SpendResponse,
  RecentActivityResponse,
  RecentActivity,
  AuthStatusResponse,
  LoginResponse,
  SetupResponse,
  LogoutResponse,
  Alert,
  AlertsResponse,
  DismissAlertResponse,
} from "./types";

const mockRecentActivity: RecentActivity[] = [
  {
    id: "ra1",
    timestamp: new Date(Date.now() - 2 * 60_000).toISOString(),
    service: "openai",
    method: "",
    endpoint: "/v1/chat/completions",
    action: "allow",
    cost_cents: 3,
  },
  {
    id: "ra2",
    timestamp: new Date(Date.now() - 5 * 60_000).toISOString(),
    service: "anthropic",
    method: "",
    endpoint: "/v1/messages",
    action: "allow",
    cost_cents: 8,
  },
  {
    id: "ra3",
    timestamp: new Date(Date.now() - 8 * 60_000).toISOString(),
    service: "openai",
    method: "",
    endpoint: "/v1/chat/completions",
    action: "deny",
    cost_cents: 0,
    deny_reason: "rate limit exceeded",
  },
  {
    id: "ra4",
    timestamp: new Date(Date.now() - 12 * 60_000).toISOString(),
    service: "binance",
    method: "GET",
    endpoint: "/api/v3/ticker/price",
    action: "allow",
    cost_cents: 0,
  },
  {
    id: "ra5",
    timestamp: new Date(Date.now() - 18 * 60_000).toISOString(),
    service: "binance",
    method: "POST",
    endpoint: "/sapi/v1/capital/withdraw",
    action: "deny",
    cost_cents: 0,
    deny_reason: "endpoint blocked",
  },
  {
    id: "ra6",
    timestamp: new Date(Date.now() - 30 * 60_000).toISOString(),
    service: "github",
    method: "DELETE",
    endpoint: "/repos/fishnet/test",
    action: "deny",
    cost_cents: 0,
    deny_reason: "destructive action blocked",
  },
];

const nowSecs = () => Math.floor(Date.now() / 1000);

const mockAlerts: Alert[] = [
  {
    id: "alert_001",
    type: "prompt_drift",
    severity: "critical",
    service: "openai",
    message: "System prompt changed. Previous: 0x3a1f\u2026c8e2 Current: 0x91b4\u2026d7f0",
    timestamp: nowSecs() - 3 * 60,
    dismissed: false,
  },
  {
    id: "alert_002",
    type: "prompt_drift",
    severity: "critical",
    service: "anthropic",
    message: "System prompt changed. Previous: 0x7e2d\u2026a1b3 Current: 0xf4c8\u202652e9",
    timestamp: nowSecs() - 18 * 60,
    dismissed: false,
  },
  {
    id: "alert_003",
    type: "prompt_size",
    severity: "warning",
    service: "openai",
    message: "Oversized prompt: ~62,500 tokens (limit: 50,000). Action: alert only.",
    timestamp: nowSecs() - 45 * 60,
    dismissed: false,
  },
  {
    id: "alert_004",
    type: "prompt_size",
    severity: "warning",
    service: "anthropic",
    message: "Prompt size 210,000 chars exceeds limit of 200,000. Action: denied.",
    timestamp: nowSecs() - 2 * 3600,
    dismissed: false,
  },
  {
    id: "alert_005",
    type: "prompt_drift",
    severity: "critical",
    service: "openai",
    message: "System prompt changed. Previous: 0x3a1f\u2026c8e2 Current: 0xbb07\u202619d3",
    timestamp: nowSecs() - 6 * 3600,
    dismissed: true,
  },
];

const routes: Record<string, (opts?: RequestInit) => unknown> = {
  // Auth routes — mock always returns authenticated
  "GET /auth/status": (): AuthStatusResponse => ({
    initialized: true,
    authenticated: true,
  }),

  "POST /auth/login": (): LoginResponse => ({
    token: "fn_sess_mock_dev_token",
    expires_at: new Date(Date.now() + 4 * 60 * 60 * 1000).toISOString(),
  }),

  "POST /auth/setup": (): SetupResponse => ({
    success: true,
    message: "password configured successfully",
  }),

  "POST /auth/logout": (): LogoutResponse => ({
    success: true,
  }),

  // Dashboard routes
  "GET /status": (): StatusResponse => ({
    proxy: "running",
    uptime_secs: 86400,
    version: "0.1.0",
    active_credentials: 4,
    total_requests_24h: 1247,
    blocked_requests_24h: 23,
    warnings: [
      {
        id: "w1",
        level: "warning",
        message: "OpenAI daily budget at 92.6% \u2014 $18.53 of $20.00 used",
        timestamp: new Date().toISOString(),
        ongoing: true,
      },
      {
        id: "w2",
        level: "critical",
        message: "System prompt hash changed for Anthropic service",
        timestamp: new Date(Date.now() - 14 * 60_000).toISOString(),
      },
    ],
  }),

  "GET /spend": (): SpendResponse => ({
    period: "24h",
    total_spent_cents: 1853,
    total_budget_cents: 3200,
    buckets: [
      { service: "openai", spent_cents: 1240, budget_cents: 1500, request_count: 847 },
      { service: "anthropic", spent_cents: 580, budget_cents: 1000, request_count: 312 },
      { service: "binance", spent_cents: 33, budget_cents: 500, request_count: 56 },
      { service: "github", spent_cents: 0, budget_cents: 200, request_count: 32 },
    ],
  }),

  "GET /activity": (): RecentActivityResponse => ({
    activities: mockRecentActivity,
  }),

  // Alerts routes — matches backend shape: { alerts: [...] }
  "GET /alerts": (): AlertsResponse => ({ alerts: mockAlerts }),

  // Dismiss: POST /alerts/dismiss with { id } in body
  "POST /alerts/dismiss": (): DismissAlertResponse => ({ success: true }),
};

function matchRoute(
  path: string,
  method: string,
): ((opts?: RequestInit) => unknown) | undefined {
  const cleanPath = path.split("?")[0];
  const key = `${method} ${cleanPath}`;
  if (routes[key]) return routes[key];
  return undefined;
}

export async function handleMock<T>(path: string, opts?: RequestInit): Promise<T> {
  await new Promise((r) => setTimeout(r, 100 + Math.random() * 200));

  const method = opts?.method ?? "GET";
  const handler = matchRoute(path, method);

  if (!handler) {
    throw new Error(`[mock] No handler for ${method} ${path}`);
  }

  return handler(opts) as T;
}
