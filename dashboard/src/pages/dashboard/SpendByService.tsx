import { Card } from "@/components/ui/Card";
import { formatDollars } from "@/lib/format";
import {
  SERVICE_LABELS,
  SERVICE_BAR_CLASSES,
  SERVICE_DOT_CLASSES,
  SERVICE_GLOW_CLASSES,
} from "@/lib/constants";
import { cn } from "@/lib/cn";
import type { SpendAnalyticsResponse } from "@/api/types";
import type { ServiceName } from "@/lib/constants";

interface SpendByServiceProps {
  spend: SpendAnalyticsResponse;
}

export function SpendByService({ spend }: SpendByServiceProps) {
  const entries = Object.entries(spend.budgets);

  return (
    <Card
      title={
        <span className="flex items-center gap-2.5">
          Spend by Service
          <span className="rounded-full bg-bg-tertiary px-2 py-0.5 font-mono text-[11px] font-medium text-text-secondary">
            {entries.length}
          </span>
        </span>
      }
      padding={false}
    >
      <div className="divide-y divide-border-subtle">
        {entries.map(([service, budget], i) => {
          const pct =
            budget.daily_limit != null && budget.daily_limit > 0
              ? (budget.spent_today / budget.daily_limit) * 100
              : 0;
          const barClass = SERVICE_BAR_CLASSES[service] ?? "bg-purple";
          const dotClass = SERVICE_DOT_CLASSES[service] ?? "bg-purple";
          const glowClass = SERVICE_GLOW_CLASSES[service] ?? "";

          return (
            <div
              key={service}
              className="animate-fade-in-up group px-6 py-4 transition-colors duration-150 hover:bg-surface-hover/50"
              style={{ animationDelay: `${i * 60}ms` }}
            >
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-2.5 text-sm font-medium text-text">
                  <span
                    className={cn(
                      "inline-block h-2 w-2 shrink-0 rounded-full",
                      dotClass,
                    )}
                  />
                  {SERVICE_LABELS[service as ServiceName] ?? service}
                </span>
                <span className="flex items-center gap-3 font-mono text-sm text-text-secondary">
                  <span className="font-semibold text-text">
                    {formatDollars(budget.spent_today)}
                  </span>
                  {budget.daily_limit != null ? (
                    <>
                      <span className="text-text-tertiary">/</span>
                      <span>{formatDollars(budget.daily_limit)}</span>
                    </>
                  ) : (
                    <span className="text-xs text-text-tertiary">no limit</span>
                  )}
                  {budget.daily_limit != null && budget.daily_limit > 0 && (
                    <span
                      className={cn(
                        "min-w-[3ch] text-right text-xs font-medium",
                        pct > 90
                          ? "text-danger"
                          : pct > 70
                            ? "text-warning"
                            : "text-text-tertiary",
                      )}
                    >
                      {Math.round(pct)}%
                    </span>
                  )}
                </span>
              </div>
              <div className="mt-2.5 h-[5px] w-full overflow-hidden rounded-full bg-bg-tertiary">
                <div
                  className={cn(
                    "h-full rounded-full transition-all duration-500 ease-out",
                    barClass,
                    pct > 60 && glowClass,
                  )}
                  style={{ width: `${Math.min(pct, 100)}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
