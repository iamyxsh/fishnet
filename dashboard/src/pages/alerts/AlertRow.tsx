import { CheckCircle2 } from "lucide-react";
import { cn } from "@/lib/cn";
import { timeAgoUnix, formatTimestamp } from "@/lib/format";
import { ALERT_TYPE_LABELS, ALERT_SEVERITY_CONFIG } from "@/lib/constants";
import type { Alert } from "@/api/types";

interface AlertRowProps {
  alert: Alert;
  isSelected: boolean;
  onToggleSelect: (id: string) => void;
  onDismiss: (id: string) => Promise<void>;
}

export function AlertRow({
  alert,
  isSelected,
  onToggleSelect,
  onDismiss,
}: AlertRowProps) {
  const config = ALERT_SEVERITY_CONFIG[alert.severity];
  const isCritical = alert.severity === "critical";

  return (
    <tr
      className={cn(
        "group border-b border-border-subtle transition-colors duration-150",
        alert.dismissed ? "opacity-40" : "hover:bg-surface-hover",
        isSelected && "bg-brand-muted/40",
      )}
    >
      {/* Checkbox */}
      <td className="py-3 pl-5 pr-0">
        {!alert.dismissed ? (
          <button
            onClick={() => onToggleSelect(alert.id)}
            className={cn(
              "flex h-4 w-4 items-center justify-center rounded border transition-all duration-150",
              isSelected
                ? "border-brand bg-brand"
                : "border-border hover:border-text-tertiary",
            )}
          >
            {isSelected && <CheckCircle2 size={10} className="text-white" />}
          </button>
        ) : (
          <div className="h-4 w-4" />
        )}
      </td>

      {/* Severity dot */}
      <td className="py-3 pr-0">
        <span
          className={cn(
            "inline-block h-2 w-2 rounded-full",
            isCritical
              ? "bg-danger shadow-[0_0_6px_rgba(239,68,68,0.5)]"
              : "bg-warning shadow-[0_0_6px_rgba(245,158,11,0.5)]",
          )}
        />
      </td>

      {/* Type */}
      <td className="py-3 pr-3">
        <span
          className={cn(
            "rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
            isCritical
              ? "bg-danger/15 text-danger"
              : "bg-warning/15 text-warning",
          )}
        >
          {ALERT_TYPE_LABELS[alert.type]}
        </span>
      </td>

      {/* Message */}
      <td className="min-w-0 py-3 pr-3">
        <p className={cn("truncate text-[13px]", config.textClass)}>
          {alert.message}
        </p>
      </td>

      {/* Service */}
      <td className="py-3 pr-3">
        <span className="text-xs capitalize text-text-secondary">
          {alert.service}
        </span>
      </td>

      {/* Time */}
      <td className="py-3 pr-3">
        <span
          className="text-xs tabular-nums text-text-tertiary"
          title={formatTimestamp(alert.timestamp)}
        >
          {timeAgoUnix(alert.timestamp)}
        </span>
      </td>

      {/* Status */}
      <td className="py-3 pr-3">
        <span
          className={cn(
            "inline-block rounded-full px-2 py-0.5 text-center text-[10px] font-semibold uppercase tracking-wider",
            alert.dismissed
              ? "bg-bg-tertiary text-text-tertiary"
              : isCritical
                ? "bg-danger/15 text-danger"
                : "bg-warning/15 text-warning",
          )}
        >
          {alert.dismissed ? "Dismissed" : "Active"}
        </span>
      </td>

      {/* Action */}
      <td className="py-3 pr-5">
        {!alert.dismissed ? (
          <button
            onClick={() => onDismiss(alert.id)}
            className={cn(
              "rounded-md px-2 py-0.5 text-xs font-medium transition-all duration-150",
              "text-text-tertiary opacity-0 group-hover:opacity-100",
              "hover:text-text",
              isCritical ? "hover:bg-danger/10" : "hover:bg-warning/10",
            )}
          >
            Dismiss
          </button>
        ) : null}
      </td>
    </tr>
  );
}
