import { Card } from "@/components/ui/Card";
import { ServiceDot } from "@/components/ui/ServiceDot";
import { CheckCircle, XCircle } from "lucide-react";
import { cn } from "@/lib/cn";
import { formatCurrency, timeAgo } from "@/lib/format";
import { SERVICE_LABELS } from "@/lib/constants";
import type { RecentActivity } from "@/api/types";
import type { ServiceName } from "@/lib/constants";

interface RecentActivityTableProps {
  activities: RecentActivity[];
}

export function RecentActivityTable({ activities }: RecentActivityTableProps) {
  return (
    <Card
      title="Recent Activity"
      action={
        <span className="text-xs font-medium text-text-tertiary">
          Recent
        </span>
      }
      padding={false}
    >
      <div className="divide-y divide-border-subtle">
        {activities.map((a, i) => {
          const isAllowed = a.action === "allow";

          return (
            <div
              key={a.id}
              className="animate-fade-in-up flex items-center gap-3 px-6 py-3.5 transition-all duration-150 hover:bg-surface-hover/60"
              style={{ animationDelay: `${i * 40}ms` }}
            >
              {/* Status icon with subtle glow */}
              {isAllowed ? (
                <CheckCircle
                  size={16}
                  className="shrink-0 text-success drop-shadow-[0_0_3px_rgba(34,197,94,0.3)]"
                />
              ) : (
                <XCircle
                  size={16}
                  className="shrink-0 text-danger drop-shadow-[0_0_3px_rgba(239,68,68,0.3)]"
                />
              )}

              {/* Service + endpoint info */}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-1.5">
                  <ServiceDot service={a.service} />
                  <span className="text-sm font-medium capitalize text-text">
                    {SERVICE_LABELS[a.service as ServiceName] ?? a.service}
                  </span>
                  <span className="truncate font-mono text-xs text-text-tertiary">
                    {a.method ? `${a.method} ` : ""}
                    {a.endpoint}
                  </span>
                </div>
                {a.deny_reason && (
                  <p className="mt-0.5 text-xs font-medium text-danger/80">
                    {a.deny_reason}
                  </p>
                )}
              </div>

              {/* Cost */}
              <span className="shrink-0 font-mono text-xs text-text-secondary tabular-nums">
                {a.cost_cents > 0 ? formatCurrency(a.cost_cents) : "—"}
              </span>

              {/* Time ago */}
              <span className="shrink-0 text-xs text-text-tertiary w-14 text-right tabular-nums">
                {timeAgo(a.timestamp)}
              </span>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
