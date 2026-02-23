export const ROUTES = {
  HOME: "/",
  SETTINGS: "/settings",
  LOGIN: "/login",
  ALERTS: "/alerts",
} as const;

export const POLLING_INTERVALS = {
  STATUS: 5_000,
  ALERTS: 30_000,
} as const;

export const SERVICES = [
  "openai",
  "anthropic",
  "binance",
  "github",
  "stripe",
  "aws",
  "gcp",
  "twilio",
  "sendgrid",
  "custom",
] as const;

export type ServiceName = (typeof SERVICES)[number];

export const SERVICE_LABELS: Record<ServiceName, string> = {
  openai: "OpenAI",
  anthropic: "Anthropic",
  binance: "Binance",
  github: "GitHub",
  stripe: "Stripe",
  aws: "AWS",
  gcp: "Google Cloud",
  twilio: "Twilio",
  sendgrid: "SendGrid",
  custom: "Custom",
};

/** Tailwind class names for service bar colors */
export const SERVICE_BAR_CLASSES: Record<string, string> = {
  openai: "bg-svc-openai",
  anthropic: "bg-svc-anthropic",
  binance: "bg-svc-binance",
  github: "bg-svc-github",
  stripe: "bg-svc-stripe",
  aws: "bg-success",
  gcp: "bg-info",
  twilio: "bg-purple",
  sendgrid: "bg-warning",
  custom: "bg-purple",
};

/** Tailwind classes for service indicator dots (bg + optional glow) */
export const SERVICE_DOT_CLASSES: Record<string, string> = {
  openai: "bg-svc-openai shadow-[0_0_4px_rgba(34,197,94,0.4)]",
  anthropic: "bg-svc-anthropic shadow-[0_0_4px_rgba(59,130,246,0.4)]",
  binance: "bg-svc-binance shadow-[0_0_4px_rgba(245,158,11,0.4)]",
  github: "bg-svc-github",
  stripe: "bg-svc-stripe shadow-[0_0_4px_rgba(139,92,246,0.4)]",
};

/** Tailwind classes for progress bar glow effects */
export const SERVICE_GLOW_CLASSES: Record<string, string> = {
  openai: "progress-glow-success",
  anthropic: "progress-glow-info",
  binance: "progress-glow-warning",
};

export const API_BASE = "/api";

// --- Alert system ---
import type { AlertType, AlertSeverity } from "@/api/types";

export const ALERT_TYPE_LABELS: Record<AlertType, string> = {
  prompt_drift: "Prompt Drift",
  prompt_size: "Prompt Size",
  budget_warning: "Budget Warning",
  budget_exceeded: "Budget Exceeded",
  onchain_denied: "Onchain Denied",
  rate_limit_hit: "Rate Limit",
};

export const ALERT_SEVERITY_CONFIG: Record<
  AlertSeverity,
  { label: string; textClass: string; bgClass: string; borderClass: string; glowClass: string }
> = {
  critical: {
    label: "Critical",
    textClass: "text-danger",
    bgClass: "bg-danger-dim",
    borderClass: "border-danger/20",
    glowClass: "danger-glow",
  },
  warning: {
    label: "Warning",
    textClass: "text-warning",
    bgClass: "bg-warning-dim",
    borderClass: "border-warning/20",
    glowClass: "warning-glow",
  },
};
