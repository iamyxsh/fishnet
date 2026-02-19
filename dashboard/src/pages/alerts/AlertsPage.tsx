import { useState, useMemo, useCallback } from "react";
import { Shield, X } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { useAlertsContext } from "@/context/alerts-context";
import { AlertRow } from "./AlertRow";
import { AlertFilters } from "./AlertFilters";
import type { StatusFilter } from "./AlertFilters";
import type { AlertType, AlertSeverity } from "@/api/types";

export default function AlertsPage() {
  const { alerts, undismissed, loading, dismiss, dismissBulk } = useAlertsContext();

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
  const hasActive = filtered.some((a) => !a.dismissed);

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
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold text-text">Alerts</h1>
          <p className="mt-0.5 text-sm text-text-secondary">
            {activeCount > 0
              ? `${activeCount} active alert${activeCount !== 1 ? "s" : ""}`
              : "No active alerts"}
          </p>
        </div>

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

      {/* Filter bar */}
      <AlertFilters
        typeFilter={typeFilter}
        severityFilter={severityFilter}
        statusFilter={statusFilter}
        onTypeChange={setTypeFilter}
        onSeverityChange={setSeverityFilter}
        onStatusChange={setStatusFilter}
        hasActive={hasActive}
        onSelectAllActive={selectAllActive}
      />

      {/* Alert list */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={<Shield size={24} className="text-text-tertiary" />}
          title="No alerts"
          subtitle="Fishnet is monitoring your agent."
        />
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
