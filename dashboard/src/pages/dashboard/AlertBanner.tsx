import { Link } from "react-router-dom";
import { AlertTriangle, XCircle, ArrowRight } from "lucide-react";
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
      {/* Icon */}
      {isCritical ? (
        <XCircle size={18} className="mt-0.5 shrink-0 text-danger" />
      ) : (
        <AlertTriangle size={18} className="mt-0.5 shrink-0 text-warning" />
      )}

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
