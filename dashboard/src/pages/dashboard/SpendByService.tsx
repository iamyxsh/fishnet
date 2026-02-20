import { Card } from "@/components/ui/Card";
import { formatDollars } from "@/lib/format";
import { SERVICE_LABELS, SERVICE_BAR_CLASSES, SERVICE_GLOW_CLASSES } from "@/lib/constants";
import { cn } from "@/lib/cn";
import type { SpendAnalyticsResponse } from "@/api/types";
import type { ServiceName } from "@/lib/constants";

interface SpendByServiceProps {
  spend: SpendAnalyticsResponse;
}

export function SpendByService({ spend }: SpendByServiceProps) {
  const entries = Object.entries(spend.budgets);

  return (
    <Card title="Spend by Service" padding={false}>
      <div className="divide-y divide-border-subtle">
        {entries.map(([service, budget], i) => {
          const pct =
            budget.daily_limit != null && budget.daily_limit > 0
              ? (budget.spent_today / budget.daily_limit) * 100
              : 0;
          const barClass =
            SERVICE_BAR_CLASSES[service] ?? "bg-purple";
          const glowClass = SERVICE_GLOW_CLASSES[service] ?? "";

          return (
            <div
              key={service}
              className="animate-fade-in-up px-6 py-4 transition-colors duration-150 hover:bg-surface-hover/50"
              style={{ animationDelay: `${i * 50}ms` }}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-text">
                  {SERVICE_LABELS[service as ServiceName] ?? service}
                </span>
                <span className="font-mono text-sm text-text-secondary">
                  <span className="font-semibold text-text">
                    {formatDollars(budget.spent_today)}
                  </span>
                  {budget.daily_limit != null ? (
                    <>
                      {" / "}
                      {formatDollars(budget.daily_limit)}
                    </>
                  ) : (
                    <span className="ml-1 text-xs text-text-tertiary">no limit</span>
                  )}
                </span>
              </div>
              <div className="mt-2.5 h-[6px] w-full overflow-hidden rounded-full bg-bg-tertiary">
                <div
                  className={cn(
                    "h-full rounded-full transition-all duration-300 ease-out",
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
