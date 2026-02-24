import { Link } from "react-router-dom";
import { ArrowRight } from "lucide-react";
import { cn } from "@/lib/cn";
import { timeAgoUnix } from "@/lib/format";
import { ROUTES, ALERT_TYPE_LABELS, ALERT_SEVERITY_CONFIG } from "@/lib/constants";
import type { Alert } from "@/api/types";

interface AlertBannerProps {
  alert: Alert;
  totalActive: number;
  onDismiss: (id: string) => void;
}

export function AlertBanner({ alert, totalActive, onDismiss }: AlertBannerProps) {
  const config = ALERT_SEVERITY_CONFIG[alert.severity];
  const isCritical = alert.severity === "critical";

  return (
    <div
      className={cn(
        "animate-fade-in-up flex items-start gap-3 rounded-xl border px-5 py-4",
        "transition-all duration-200",
        config.borderClass,
        config.bgClass,
        config.glowClass,
      )}
    >
      {/* Severity dot */}
      <span
        className={cn(
          "mt-2 inline-block h-2 w-2 shrink-0 rounded-full",
          isCritical ? "bg-danger shadow-[0_0_6px_rgba(239,68,68,0.5)]" : "bg-warning shadow-[0_0_6px_rgba(245,158,11,0.5)]",
        )}
      />

      {/* Content */}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          {/* Type badge */}
          <span
            className={cn(
              "shrink-0 rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
              isCritical
                ? "bg-danger/15 text-danger"
                : "bg-warning/15 text-warning",
            )}
          >
            {ALERT_TYPE_LABELS[alert.type]}
          </span>
          <span className="text-xs text-text-tertiary">
            {timeAgoUnix(alert.timestamp)}
          </span>
        </div>
        <p className={cn("mt-1 text-sm font-medium", config.textClass)}>
          {alert.message}
        </p>
      </div>

      {/* Actions */}
      <div className="flex shrink-0 items-center gap-2">
        {/* View all link */}
        {totalActive > 1 && (
          <Link
            to={ROUTES.ALERTS}
            className={cn(
              "flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium transition-all duration-150",
              "text-text-tertiary hover:text-text",
              isCritical ? "hover:bg-danger/10" : "hover:bg-warning/10",
            )}
          >
            {totalActive - 1} more
            <ArrowRight size={12} />
          </Link>
        )}

        {/* Dismiss */}
        <button
          onClick={() => onDismiss(alert.id)}
          className={cn(
            "shrink-0 rounded-md px-2 py-0.5 text-xs font-medium transition-all duration-150",
            "text-text-tertiary hover:text-text",
            isCritical ? "hover:bg-danger/10" : "hover:bg-warning/10",
          )}
        >
          Dismiss
        </button>
      </div>
    </div>
  );
}
