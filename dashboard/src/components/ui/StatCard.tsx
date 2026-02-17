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
  return (
    <div
      className={cn(
        "stat-card-glow group relative overflow-hidden rounded-xl border border-border bg-surface p-5",
        className,
      )}
    >
      {/* Top accent line with gradient fade */}
      {accentColor && (
        <div className="absolute inset-x-0 top-0 h-[2px]">
          <div className={cn("h-full w-full opacity-60", accentColor)} />
          {/* Glow reflection below the line */}
          <div
            className={cn(
              "absolute inset-x-0 top-0 h-8 opacity-[0.03]",
              accentColor,
            )}
            style={{ filter: "blur(12px)" }}
          />
        </div>
      )}

      <div className="flex items-start justify-between">
        {/* Icon container with subtle glow on hover */}
        {icon && (
          <div
            className={cn(
              "flex h-9 w-9 items-center justify-center rounded-lg transition-all duration-200",
              accentColor
                ? "bg-brand-muted text-brand group-hover:bg-brand/15 group-hover:shadow-[0_0_12px_rgba(230,57,70,0.12)]"
                : "bg-bg-tertiary text-text-secondary",
            )}
          >
            {icon}
          </div>
        )}

        {/* Trend badge */}
        {trend && (
          <div className="text-xs font-medium">{trend}</div>
        )}
      </div>

      {/* Value with smooth number appearance */}
      <div className="mt-3">
        <p className="font-mono text-[28px] font-bold leading-none tracking-tight text-text transition-colors duration-150">
          {value}
        </p>
      </div>

      {/* Label */}
      <p className="mt-1.5 text-[11px] font-semibold uppercase tracking-[0.06em] text-text-tertiary">
        {label}
      </p>

      {/* Optional progress bar with glow */}
      {progress && (
        <div className="mt-3 h-[3px] w-full overflow-hidden rounded-full bg-bg-tertiary">
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
        <p className="mt-1.5 font-mono text-xs text-text-tertiary">{subtitle}</p>
      )}
    </div>
  );
}
