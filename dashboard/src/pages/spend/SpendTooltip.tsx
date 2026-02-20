import type { Payload } from "recharts/types/component/DefaultTooltipContent";
import { ServiceDot } from "@/components/ui/ServiceDot";
import { SERVICE_LABELS } from "@/lib/constants";

interface SpendTooltipProps {
  active?: boolean;
  payload?: Payload<number, string>[];
  label?: string;
}

export function SpendTooltip({ active, payload, label }: SpendTooltipProps) {
  if (!active || !payload?.length) return null;

  const dateLabel = new Date(label + "T00:00:00").toLocaleDateString("en-US", {
    weekday: "short",
    month: "short",
    day: "numeric",
  });

  const total = payload.reduce(
    (sum: number, p: Payload<number, string>) => sum + (p.value ?? 0),
    0,
  );

  return (
    <div className="rounded-lg border border-border bg-surface p-3 shadow-lg">
      <p className="mb-2 text-xs font-medium text-text">{dateLabel}</p>
      <div className="space-y-1">
        {payload.map((entry: Payload<number, string>) => (
          <div
            key={String(entry.dataKey)}
            className="flex items-center justify-between gap-6"
          >
            <div className="flex items-center gap-2">
              <ServiceDot service={String(entry.dataKey)} />
              <span className="text-xs text-text-secondary">
                {SERVICE_LABELS[
                  entry.dataKey as keyof typeof SERVICE_LABELS
                ] ?? entry.dataKey}
              </span>
            </div>
            <span className="font-mono text-xs font-medium text-text">
              ${(entry.value ?? 0).toFixed(2)}
            </span>
          </div>
        ))}
      </div>
      <div className="mt-2 flex justify-between border-t border-border-subtle pt-2">
        <span className="text-xs font-medium text-text-secondary">Total</span>
        <span className="font-mono text-xs font-bold text-text">
          ${total.toFixed(2)}
        </span>
      </div>
    </div>
  );
}
