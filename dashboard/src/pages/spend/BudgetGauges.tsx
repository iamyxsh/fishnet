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

const SIZE = 76;
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

  const serviceColor = SERVICE_CHART_COLORS[service] ?? "#22C55E";
  const strokeColor = !hasLimit
    ? "#71717A"
    : isDanger
      ? "#EF4444"
      : isWarning
        ? "#F59E0B"
        : serviceColor;

  const accentColor = isDanger
    ? "#EF4444"
    : isWarning
      ? "#F59E0B"
      : serviceColor;

  return (
    <div
      className={cn(
        "animate-fade-in-up stat-card-glow group relative flex flex-col items-center overflow-hidden rounded-xl border px-3 py-4",
        isDanger
          ? "border-danger/20 bg-danger-dim"
          : isWarning
            ? "border-warning/15 bg-warning-dim"
            : "border-border bg-surface",
      )}
      style={{ animationDelay: `${index * 60}ms` }}
    >
      {/* Top accent line with glow reflection — StatCard pattern */}
      <div className="absolute inset-x-0 top-0 h-[2px]">
        <div
          className="h-full w-full opacity-60"
          style={{ backgroundColor: accentColor }}
        />
        <div
          className="absolute inset-x-0 top-0 h-8 opacity-[0.04]"
          style={{ backgroundColor: accentColor, filter: "blur(12px)" }}
        />
      </div>

      {/* Gauge with ambient radial glow */}
      <div className="relative">
        {hasLimit && pct > 40 && (
          <div
            className="absolute inset-0 rounded-full transition-opacity duration-700"
            style={{
              backgroundColor: strokeColor,
              opacity: 0.06,
              filter: "blur(10px)",
              transform: "scale(1.3)",
            }}
          />
        )}
        <svg width={SIZE} height={SIZE} className="-rotate-90">
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            stroke="var(--color-bg-tertiary)"
            strokeWidth={STROKE}
          />
          {hasLimit ? (
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
              style={
                pct > 70
                  ? { filter: `drop-shadow(0 0 4px ${strokeColor}40)` }
                  : undefined
              }
            />
          ) : (
            /* Dashed ring placeholder for uncapped services */
            <circle
              cx={SIZE / 2}
              cy={SIZE / 2}
              r={RADIUS}
              fill="none"
              stroke="var(--color-border)"
              strokeWidth={STROKE}
              strokeDasharray="4 6"
              opacity={0.4}
            />
          )}
        </svg>
        {/* Percentage centered in gauge */}
        <span
          className={cn(
            "absolute inset-0 flex items-center justify-center font-mono text-xs font-bold",
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

      <p className="mt-2 text-xs font-semibold text-text">
        {SERVICE_LABELS[service as keyof typeof SERVICE_LABELS] ?? service}
      </p>

      {hasLimit ? (
        <p className="mt-0.5 font-mono text-[11px] text-text-secondary">
          <span className="font-bold text-text">
            ${budget.spent_today.toFixed(2)}
          </span>{" "}
          <span className="text-text-tertiary">
            / ${budget.daily_limit!.toFixed(2)}
          </span>
        </p>
      ) : (
        <p className="mt-0.5 text-[11px] italic text-text-tertiary">No limit</p>
      )}
    </div>
  );
}
