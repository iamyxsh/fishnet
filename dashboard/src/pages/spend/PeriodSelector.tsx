import { FilterPill } from "@/components/ui/FilterPill";
import type { SpendDays } from "@/api/endpoints/spend-analytics";

interface PeriodSelectorProps {
  days: SpendDays;
  onChange: (days: SpendDays) => void;
}

const PERIODS: { value: SpendDays; label: string }[] = [
  { value: 7, label: "7 days" },
  { value: 14, label: "14 days" },
  { value: 30, label: "30 days" },
];

export function PeriodSelector({ days, onChange }: PeriodSelectorProps) {
  return (
    <div className="flex items-center gap-1 rounded-full border border-border-subtle bg-bg-secondary/80 p-1">
      {PERIODS.map((p) => (
        <FilterPill
          key={p.value}
          active={days === p.value}
          onClick={() => onChange(p.value)}
        >
          {p.label}
        </FilterPill>
      ))}
    </div>
  );
}
