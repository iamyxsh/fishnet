import { Card } from "@/components/ui/Card";
import { formatCurrency } from "@/lib/format";
import { SERVICE_LABELS, SERVICE_BAR_CLASSES, SERVICE_GLOW_CLASSES } from "@/lib/constants";
import { cn } from "@/lib/cn";
import type { SpendResponse } from "@/api/types";
import type { ServiceName } from "@/lib/constants";

interface SpendByServiceProps {
  spend: SpendResponse;
}

export function SpendByService({ spend }: SpendByServiceProps) {
  return (
    <Card title="Spend by Service" padding={false}>
      <div className="divide-y divide-border-subtle">
        {spend.buckets.map((bucket, i) => {
          const pct =
            bucket.budget_cents > 0
              ? (bucket.spent_cents / bucket.budget_cents) * 100
              : 0;
          const barClass =
            SERVICE_BAR_CLASSES[bucket.service] ?? "bg-purple";
          const glowClass = SERVICE_GLOW_CLASSES[bucket.service] ?? "";

          return (
            <div
              key={bucket.service}
              className="animate-fade-in-up px-6 py-4 transition-colors duration-150 hover:bg-surface-hover/50"
              style={{ animationDelay: `${i * 50}ms` }}
            >
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-text">
                  {SERVICE_LABELS[bucket.service as ServiceName] ?? bucket.service}
                </span>
                <span className="font-mono text-sm text-text-secondary">
                  <span className="font-semibold text-text">
                    {formatCurrency(bucket.spent_cents)}
                  </span>
                  {" / "}
                  {formatCurrency(bucket.budget_cents)}
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
