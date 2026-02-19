import { AlertTriangle, XCircle, CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/cn";
import { timeAgoUnix, formatTimestamp } from "@/lib/format";
import { ALERT_TYPE_LABELS, ALERT_SEVERITY_CONFIG } from "@/lib/constants";
import type { Alert } from "@/api/types";

interface AlertRowProps {
  alert: Alert;
  index: number;
  isSelected: boolean;
  onToggleSelect: (id: string) => void;
  onDismiss: (id: string) => Promise<void>;
}

export function AlertRow({
  alert,
  index,
  isSelected,
  onToggleSelect,
  onDismiss,
}: AlertRowProps) {
  const config = ALERT_SEVERITY_CONFIG[alert.severity];
  const isCritical = alert.severity === "critical";

  return (
    <div
      className={cn(
        "animate-fade-in-up flex items-center gap-3 px-6 py-4 transition-all duration-150",
        alert.dismissed ? "opacity-50" : "hover:bg-surface-hover/60",
        isSelected && "bg-brand-muted/40",
      )}
      style={{ animationDelay: `${index * 40}ms` }}
    >
      {/* Checkbox (only for active alerts) */}
      {!alert.dismissed ? (
        <button
          onClick={() => onToggleSelect(alert.id)}
          className={cn(
            "flex h-4 w-4 shrink-0 items-center justify-center rounded border transition-all duration-150",
            isSelected
              ? "border-brand bg-brand"
              : "border-border hover:border-text-tertiary",
          )}
        >
          {isSelected && <CheckCircle2 size={10} className="text-white" />}
        </button>
      ) : (
        <div className="w-4 shrink-0" />
      )}

      {/* Severity icon */}
      {isCritical ? (
        <XCircle
          size={16}
          className="shrink-0 text-danger drop-shadow-[0_0_3px_rgba(239,68,68,0.3)]"
        />
      ) : (
        <AlertTriangle
          size={16}
          className="shrink-0 text-warning drop-shadow-[0_0_3px_rgba(245,158,11,0.3)]"
        />
      )}

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

      {/* Message */}
      <p className={cn("min-w-0 flex-1 truncate text-sm", config.textClass)}>
        {alert.message}
      </p>

      {/* Timestamp */}
      <span
        className="shrink-0 text-xs text-text-tertiary tabular-nums"
        title={formatTimestamp(alert.timestamp)}
      >
        {timeAgoUnix(alert.timestamp)}
      </span>

      {/* Status pill */}
      <span
        className={cn(
          "w-20 shrink-0 rounded-full px-2 py-0.5 text-center text-[10px] font-semibold uppercase tracking-wider",
          alert.dismissed
            ? "bg-bg-tertiary text-text-tertiary"
            : isCritical
              ? "bg-danger/15 text-danger"
              : "bg-warning/15 text-warning",
        )}
      >
        {alert.dismissed ? "Dismissed" : "Active"}
      </span>

      {/* Dismiss action */}
      {!alert.dismissed ? (
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
      ) : (
        <div className="w-14 shrink-0" />
      )}
    </div>
  );
}
