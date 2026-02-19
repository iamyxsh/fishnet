import { useState, useMemo, useCallback } from "react";
import {
  AlertTriangle,
  XCircle,
  Shield,
  CheckCircle2,
  X,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { timeAgoUnix, formatTimestamp } from "@/lib/format";
import { Card } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { useAlerts } from "@/hooks/use-alerts";
import {
  ALERT_TYPE_LABELS,
  ALERT_SEVERITY_CONFIG,
} from "@/lib/constants";
import type { AlertType, AlertSeverity } from "@/api/types";

/* ── Filter options ────────────────────────────────── */
const ALL_TYPES: AlertType[] = [
  "prompt_drift",
  "prompt_size",
  "budget_warning",
  "budget_exceeded",
  "onchain_denied",
  "rate_limit_hit",
];

type StatusFilter = "all" | "active" | "dismissed";

/* ── Page ──────────────────────────────────────────── */
export default function AlertsPage() {
  const { alerts, undismissed, loading, dismiss, dismissBulk } = useAlerts();

  // Filters
  const [typeFilter, setTypeFilter] = useState<AlertType | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<AlertSeverity | "all">("all");
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");

  // Selection for bulk dismiss
  const [selected, setSelected] = useState<Set<string>>(new Set());

  const filtered = useMemo(() => {
    return alerts
      .filter((a) => typeFilter === "all" || a.type === typeFilter)
      .filter((a) => severityFilter === "all" || a.severity === severityFilter)
      .filter((a) => {
        if (statusFilter === "active") return !a.dismissed;
        if (statusFilter === "dismissed") return a.dismissed;
        return true;
      })
      .sort((a, b) => b.timestamp - a.timestamp);
  }, [alerts, typeFilter, severityFilter, statusFilter]);

  const toggleSelect = useCallback((id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const selectAllActive = useCallback(() => {
    const activeIds = filtered.filter((a) => !a.dismissed).map((a) => a.id);
    setSelected(new Set(activeIds));
  }, [filtered]);

  const clearSelection = useCallback(() => setSelected(new Set()), []);

  const handleBulkDismiss = useCallback(async () => {
    const ids = Array.from(selected);
    if (ids.length === 0) return;
    await dismissBulk(ids);
    setSelected(new Set());
  }, [selected, dismissBulk]);

  const activeCount = undismissed.length;

  if (loading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-12 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  return (
    <div className="page-enter space-y-6">
      {/* ── Header ────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-text">Alerts</h1>
          <p className="mt-0.5 text-sm text-text-secondary">
            {activeCount > 0
              ? `${activeCount} active alert${activeCount !== 1 ? "s" : ""}`
              : "No active alerts"}
          </p>
        </div>

        {/* Bulk actions */}
        {selected.size > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-tertiary">
              {selected.size} selected
            </span>
            <button
              onClick={handleBulkDismiss}
              className="rounded-lg bg-brand px-3 py-1.5 text-xs font-medium text-white transition-all duration-150 hover:bg-brand-hover"
            >
              Dismiss Selected
            </button>
            <button
              onClick={clearSelection}
              className="rounded-lg px-2 py-1.5 text-xs text-text-tertiary transition-all duration-150 hover:bg-surface-hover hover:text-text"
            >
              <X size={14} />
            </button>
          </div>
        )}
      </div>

      {/* ── Filter bar ────────────────────────────── */}
      <div className="flex flex-wrap items-center gap-2">
        {/* Type filter */}
        <FilterPill
          active={typeFilter === "all"}
          onClick={() => setTypeFilter("all")}
        >
          All Types
        </FilterPill>
        {ALL_TYPES.map((t) => (
          <FilterPill
            key={t}
            active={typeFilter === t}
            onClick={() => setTypeFilter(t)}
          >
            {ALERT_TYPE_LABELS[t]}
          </FilterPill>
        ))}

        <div className="mx-1 h-4 w-px bg-border" />

        {/* Severity filter */}
        <FilterPill
          active={severityFilter === "all"}
          onClick={() => setSeverityFilter("all")}
        >
          All Severity
        </FilterPill>
        <FilterPill
          active={severityFilter === "critical"}
          onClick={() => setSeverityFilter("critical")}
          color="danger"
        >
          Critical
        </FilterPill>
        <FilterPill
          active={severityFilter === "warning"}
          onClick={() => setSeverityFilter("warning")}
          color="warning"
        >
          Warning
        </FilterPill>

        <div className="mx-1 h-4 w-px bg-border" />

        {/* Status filter */}
        <FilterPill
          active={statusFilter === "all"}
          onClick={() => setStatusFilter("all")}
        >
          All
        </FilterPill>
        <FilterPill
          active={statusFilter === "active"}
          onClick={() => setStatusFilter("active")}
        >
          Active
        </FilterPill>
        <FilterPill
          active={statusFilter === "dismissed"}
          onClick={() => setStatusFilter("dismissed")}
        >
          Dismissed
        </FilterPill>

        {/* Select all active */}
        {filtered.some((a) => !a.dismissed) && (
          <>
            <div className="mx-1 h-4 w-px bg-border" />
            <button
              onClick={selectAllActive}
              className="text-xs text-text-tertiary transition-colors duration-150 hover:text-brand"
            >
              Select all active
            </button>
          </>
        )}
      </div>

      {/* ── Alert list ────────────────────────────── */}
      {filtered.length === 0 ? (
        <EmptyState />
      ) : (
        <Card padding={false} hover={false}>
          <div className="divide-y divide-border-subtle">
            {filtered.map((alert, i) => (
              <AlertRow
                key={alert.id}
                alert={alert}
                index={i}
                isSelected={selected.has(alert.id)}
                onToggleSelect={toggleSelect}
                onDismiss={dismiss}
              />
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

/* ── AlertRow ──────────────────────────────────────── */

function AlertRow({
  alert,
  index,
  isSelected,
  onToggleSelect,
  onDismiss,
}: {
  alert: import("@/api/types").Alert;
  index: number;
  isSelected: boolean;
  onToggleSelect: (id: string) => void;
  onDismiss: (id: string) => Promise<void>;
}) {
  const config = ALERT_SEVERITY_CONFIG[alert.severity];
  const isCritical = alert.severity === "critical";

  return (
    <div
      className={cn(
        "animate-fade-in-up flex items-center gap-3 px-6 py-4 transition-all duration-150",
        alert.dismissed
          ? "opacity-50"
          : "hover:bg-surface-hover/60",
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
          {isSelected && (
            <CheckCircle2 size={10} className="text-white" />
          )}
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

/* ── FilterPill ────────────────────────────────────── */

function FilterPill({
  active,
  onClick,
  color,
  children,
}: {
  active: boolean;
  onClick: () => void;
  color?: "danger" | "warning";
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-full px-3 py-1 text-xs font-medium transition-all duration-150",
        active
          ? color === "danger"
            ? "bg-danger/15 text-danger"
            : color === "warning"
              ? "bg-warning/15 text-warning"
              : "bg-brand-muted text-brand"
          : "bg-surface text-text-tertiary hover:bg-surface-hover hover:text-text",
      )}
    >
      {children}
    </button>
  );
}

/* ── Empty State ───────────────────────────────────── */

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center py-20">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-surface-raised">
        <Shield size={24} className="text-text-tertiary" />
      </div>
      <p className="mt-4 text-sm font-medium text-text-secondary">
        No alerts
      </p>
      <p className="mt-1 text-xs text-text-tertiary">
        Fishnet is monitoring your agent.
      </p>
    </div>
  );
}
