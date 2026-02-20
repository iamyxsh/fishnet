import { FilterPill } from "@/components/ui/FilterPill";
import { ALERT_TYPE_LABELS } from "@/lib/constants";
import type { AlertType, AlertSeverity } from "@/api/types";

const ALL_TYPES: AlertType[] = [
  "prompt_drift",
  "prompt_size",
  "budget_warning",
  "budget_exceeded",
  "onchain_denied",
  "rate_limit_hit",
];

export type StatusFilter = "all" | "active" | "dismissed";

interface AlertFiltersProps {
  typeFilter: AlertType | "all";
  severityFilter: AlertSeverity | "all";
  statusFilter: StatusFilter;
  onTypeChange: (v: AlertType | "all") => void;
  onSeverityChange: (v: AlertSeverity | "all") => void;
  onStatusChange: (v: StatusFilter) => void;
  hasActive: boolean;
  onSelectAllActive: () => void;
}

export function AlertFilters({
  typeFilter,
  severityFilter,
  statusFilter,
  onTypeChange,
  onSeverityChange,
  onStatusChange,
  hasActive,
  onSelectAllActive,
}: AlertFiltersProps) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {/* Type */}
      <FilterPill active={typeFilter === "all"} onClick={() => onTypeChange("all")}>
        All Types
      </FilterPill>
      {ALL_TYPES.map((t) => (
        <FilterPill key={t} active={typeFilter === t} onClick={() => onTypeChange(t)}>
          {ALERT_TYPE_LABELS[t]}
        </FilterPill>
      ))}

      <div className="mx-1 h-4 w-px bg-border" />

      {/* Severity */}
      <FilterPill active={severityFilter === "all"} onClick={() => onSeverityChange("all")}>
        All Severity
      </FilterPill>
      <FilterPill active={severityFilter === "critical"} onClick={() => onSeverityChange("critical")} color="danger">
        Critical
      </FilterPill>
      <FilterPill active={severityFilter === "warning"} onClick={() => onSeverityChange("warning")} color="warning">
        Warning
      </FilterPill>

      <div className="mx-1 h-4 w-px bg-border" />

      {/* Status */}
      <FilterPill active={statusFilter === "all"} onClick={() => onStatusChange("all")}>
        All
      </FilterPill>
      <FilterPill active={statusFilter === "active"} onClick={() => onStatusChange("active")}>
        Active
      </FilterPill>
      <FilterPill active={statusFilter === "dismissed"} onClick={() => onStatusChange("dismissed")}>
        Dismissed
      </FilterPill>

      {/* Select all active */}
      {hasActive && (
        <>
          <div className="mx-1 h-4 w-px bg-border" />
          <button
            onClick={onSelectAllActive}
            className="text-xs text-text-tertiary transition-colors duration-150 hover:text-brand"
          >
            Select all active
          </button>
        </>
      )}
    </div>
  );
}
