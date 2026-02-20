import { useState, useEffect } from "react";
import { SERVICE_LABELS, SERVICE_CHART_COLORS } from "@/lib/constants";
import { cn } from "@/lib/cn";
import type { ServiceBudget } from "@/api/types";

interface BudgetGaugesProps {
  budgets: Record<string, ServiceBudget>;
}

export function BudgetGauges({ budgets }: BudgetGaugesProps) {
  const entries = Object.entries(budgets);

  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
      {entries.map(([service, budget], i) => (
        <BudgetGauge
          key={service}
          service={service}
          budget={budget}
          index={i}
        />
      ))}
    </div>
  );
}

const SIZE = 72;
const STROKE = 5;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

interface BudgetGaugeProps {
  service: string;
  budget: ServiceBudget;
  index: number;
}

function BudgetGauge({ service, budget, index }: BudgetGaugeProps) {
  const hasLimit = budget.daily_limit !== null;
  const pct = hasLimit
    ? Math.min((budget.spent_today / budget.daily_limit!) * 100, 100)
    : 0;

  const targetOffset = CIRCUMFERENCE - (pct / 100) * CIRCUMFERENCE;

  const [offset, setOffset] = useState(CIRCUMFERENCE);
  useEffect(() => {
    const timer = setTimeout(() => setOffset(targetOffset), index * 80 + 50);
    return () => clearTimeout(timer);
  }, [targetOffset, index]);

  const isWarning = hasLimit && pct > 70 && pct <= 90;
  const isDanger = hasLimit && pct > 90;

  const strokeColor = !hasLimit
    ? "#71717A"
    : isDanger
      ? "#EF4444"
      : isWarning
        ? "#F59E0B"
        : SERVICE_CHART_COLORS[service] ?? "#22C55E";

  return (
    <div
      className={cn(
        "animate-fade-in-up flex flex-col items-center rounded-xl border bg-surface px-3 py-4 transition-colors",
        isDanger
          ? "border-danger/20"
          : isWarning
            ? "border-warning/15"
            : "border-border",
      )}
      style={{ animationDelay: `${index * 60}ms` }}
    >
      <div className="relative">
        <svg width={SIZE} height={SIZE} className="-rotate-90">
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            stroke="var(--color-bg-tertiary)"
            strokeWidth={STROKE}
          />
          {hasLimit && (
            <circle
              cx={SIZE / 2}
              cy={SIZE / 2}
              r={RADIUS}
              fill="none"
              stroke={strokeColor}
              strokeWidth={STROKE}
              strokeLinecap="round"
              strokeDasharray={CIRCUMFERENCE}
              strokeDashoffset={offset}
              className="transition-[stroke-dashoffset] duration-700 ease-out"
            />
          )}
        </svg>
        {/* Percentage label centered in gauge */}
        <span
          className={cn(
            "absolute inset-0 flex items-center justify-center font-mono text-[11px] font-semibold",
            isDanger
              ? "text-danger"
              : isWarning
                ? "text-warning"
                : hasLimit
                  ? "text-text"
                  : "text-text-tertiary",
          )}
        >
          {hasLimit ? `${Math.round(pct)}%` : "—"}
        </span>
      </div>

      <p className="mt-1.5 text-xs font-medium text-text">
        {SERVICE_LABELS[service as keyof typeof SERVICE_LABELS] ?? service}
      </p>

      {hasLimit ? (
        <p className="mt-0.5 font-mono text-[10px] text-text-secondary">
          ${budget.spent_today.toFixed(2)}{" "}
          <span className="text-text-tertiary">
            / ${budget.daily_limit!.toFixed(2)}
          </span>
        </p>
      ) : (
        <p className="mt-0.5 text-[10px] text-text-tertiary">No limit set</p>
      )}
    </div>
  );
}
