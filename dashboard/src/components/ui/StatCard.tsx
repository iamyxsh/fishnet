import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

interface StatCardProps {
  label: string;
  value: string | number;
  icon?: ReactNode;
  /** Trend badge shown top-right, e.g. "↗ +12.3%" */
  trend?: ReactNode;
  /** Extra info below value, e.g. "$20.00 limit" */
  subtitle?: ReactNode;
  /** Accent bar at top of card — pass a color class like "bg-success" */
  accentColor?: string;
  /** Optional progress bar (0-100) */
  progress?: { value: number; color?: string };
  className?: string;
}

const ICON_STYLES: Record<string, string> = {
  "bg-success": "bg-success-dim text-success",
  "bg-danger": "bg-danger-dim text-danger",
  "bg-brand": "bg-brand-muted text-brand",
  "bg-info": "bg-info-dim text-info",
  "bg-warning": "bg-warning-dim text-warning",
  "bg-purple": "bg-purple-dim text-purple",
};

/** CSS variable name for each accent — used for the corner glow */
const ACCENT_VARS: Record<string, string> = {
  "bg-success": "--color-success",
  "bg-danger": "--color-danger",
  "bg-brand": "--color-brand",
  "bg-info": "--color-info",
  "bg-warning": "--color-warning",
  "bg-purple": "--color-purple",
};

/** Hover border color per accent */
const HOVER_BORDERS: Record<string, string> = {
  "bg-success": "hover:border-success/25",
  "bg-danger": "hover:border-danger/25",
  "bg-brand": "hover:border-brand/25",
  "bg-info": "hover:border-info/25",
  "bg-warning": "hover:border-warning/25",
  "bg-purple": "hover:border-purple/25",
};

export function StatCard({
  label,
  value,
  icon,
  trend,
  subtitle,
  accentColor,
  progress,
  className,
}: StatCardProps) {
  const accentVar = accentColor ? ACCENT_VARS[accentColor] : undefined;

  return (
    <div
      className={cn(
        "group relative flex h-full flex-col overflow-hidden rounded-xl border border-border bg-surface px-6 pb-6 pt-5 transition-all duration-200",
        "hover:-translate-y-0.5",
        accentColor && (HOVER_BORDERS[accentColor] ?? "hover:border-brand/25"),
        className,
      )}
    >
      {/* Corner glow — subtle radial gradient from top-left */}
      {accentVar && (
        <div
          className="pointer-events-none absolute -left-10 -top-10 h-32 w-32 rounded-full opacity-[0.06] transition-opacity duration-300 group-hover:opacity-[0.10]"
          style={{
            background: `radial-gradient(circle, var(${accentVar}), transparent 70%)`,
          }}
        />
      )}

      {/* Top accent line */}
      {accentColor && (
        <div className="absolute inset-x-0 top-0 h-[2px]">
          <div className={cn("h-full w-full opacity-70", accentColor)} />
        </div>
      )}

      {/* Row: icon left, trend right */}
      <div className="flex items-start justify-between">
        {icon && (
          <div
            className={cn(
              "flex h-10 w-10 items-center justify-center rounded-lg",
              accentColor
                ? ICON_STYLES[accentColor] ?? "bg-brand-muted text-brand"
                : "bg-bg-tertiary text-text-secondary",
            )}
          >
            {icon}
          </div>
        )}
        {trend && (
          <div className="text-xs font-medium">{trend}</div>
        )}
      </div>

      {/* Label → Value block (label on top, value below) */}
      <div className="mt-auto pt-5">
        <p className="text-[11px] font-semibold uppercase tracking-[0.08em] text-text-tertiary">
          {label}
        </p>
        <p className="mt-1 font-mono text-2xl font-bold leading-none tracking-tight text-text">
          {value}
        </p>
      </div>

      {/* Optional progress bar */}
      {progress && (
        <div className="mt-4 h-1 w-full overflow-hidden rounded-full bg-bg-tertiary">
          <div
            className={cn(
              "h-full rounded-full transition-all duration-700 ease-out",
              progress.color ?? "bg-brand",
              progress.value > 80 && "progress-glow-brand",
            )}
            style={{ width: `${Math.min(progress.value, 100)}%` }}
          />
        </div>
      )}

      {/* Subtitle */}
      {subtitle && (
        <p className="mt-2 font-mono text-xs text-text-tertiary">{subtitle}</p>
      )}
    </div>
  );
}
