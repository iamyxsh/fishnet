import { FilterPill } from "@/components/ui/FilterPill";
import type { PermitStatus } from "@/api/types";
import type { PermitDays } from "@/api/endpoints/onchain";

interface PermitFiltersProps {
  days: PermitDays;
  statusFilter: PermitStatus | "all";
  onDaysChange: (d: PermitDays) => void;
  onStatusChange: (s: PermitStatus | "all") => void;
}

const PERIOD_OPTIONS: PermitDays[] = [7, 14, 30];

export function PermitFilters({
  days,
  statusFilter,
  onDaysChange,
  onStatusChange,
}: PermitFiltersProps) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      {/* Period — segmented control */}
      <div className="flex items-center gap-0.5 rounded-full border border-border-subtle bg-bg-secondary/80 p-1">
        {PERIOD_OPTIONS.map((d) => (
          <FilterPill key={d} active={days === d} onClick={() => onDaysChange(d)}>
            {d}d
          </FilterPill>
        ))}
      </div>

      <div className="h-5 w-px bg-border-subtle" />

      {/* Status — segmented control */}
      <div className="flex items-center gap-0.5 rounded-full border border-border-subtle bg-bg-secondary/80 p-1">
        <FilterPill
          active={statusFilter === "all"}
          onClick={() => onStatusChange("all")}
        >
          All
        </FilterPill>
        <FilterPill
          active={statusFilter === "approved"}
          onClick={() => onStatusChange("approved")}
        >
          Approved
        </FilterPill>
        <FilterPill
          active={statusFilter === "denied"}
          onClick={() => onStatusChange("denied")}
          color="danger"
        >
          Denied
        </FilterPill>
      </div>
    </div>
  );
}
