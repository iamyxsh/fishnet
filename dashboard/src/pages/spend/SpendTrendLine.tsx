import { useMemo } from "react";
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/cn";
import type { DailySpendEntry } from "@/api/types";
import type { SpendDays } from "@/api/endpoints/spend-analytics";
import type { Payload } from "recharts/types/component/DefaultTooltipContent";

interface SpendTrendLineProps {
  daily: DailySpendEntry[];
  days: SpendDays;
}

interface TrendPoint {
  date: string;
  cumulative: number | null;
  projected: number | null;
}

export function SpendTrendLine({ daily, days }: SpendTrendLineProps) {
  const chartData = useMemo(() => {
    // Sum all services per date, then accumulate
    const byDate = new Map<string, number>();
    for (const entry of daily) {
      byDate.set(entry.date, (byDate.get(entry.date) ?? 0) + entry.cost_usd);
    }

    const sorted = Array.from(byDate.entries()).sort(([a], [b]) =>
      a.localeCompare(b),
    );

    let cumulative = 0;
    const data: TrendPoint[] = sorted.map(([date, amount]) => {
      cumulative += amount;
      return { date, cumulative: +cumulative.toFixed(2), projected: null };
    });

    // Linear projection (up to 7 days)
    if (data.length >= 2) {
      const daysElapsed = data.length;
      const avgDaily = cumulative / daysElapsed;
      const remaining = Math.min(days - daysElapsed, 7);

      // Bridge: last actual point also has projected value for continuity
      const lastPoint = data[data.length - 1];
      lastPoint.projected = lastPoint.cumulative;

      let projCumulative = cumulative;
      for (let i = 1; i <= remaining; i++) {
        const baseDate = new Date(sorted[sorted.length - 1][0] + "T00:00:00");
        baseDate.setDate(baseDate.getDate() + i);
        const dateStr = baseDate.toISOString().slice(0, 10);

        projCumulative += avgDaily;
        data.push({
          date: dateStr,
          cumulative: null,
          projected: +projCumulative.toFixed(2),
        });
      }
    }

    return data;
  }, [daily, days]);

  const formatDate = (dateStr: string) => {
    const d = new Date(dateStr + "T00:00:00");
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  };

  const legend = (
    <div className="flex items-center gap-2">
      <div className="flex items-center gap-1.5 rounded-full bg-bg-tertiary/50 px-2.5 py-1">
        <svg width="14" height="2" className="shrink-0">
          <line x1="0" y1="1" x2="14" y2="1" stroke="var(--color-brand)" strokeWidth="2" />
        </svg>
        <span className="text-[11px] text-text-secondary">Actual</span>
      </div>
      <div className="flex items-center gap-1.5 rounded-full bg-bg-tertiary/50 px-2.5 py-1">
        <svg width="14" height="2" className="shrink-0">
          <line x1="0" y1="1" x2="14" y2="1" stroke="var(--color-brand)" strokeWidth="1.5" strokeDasharray="3 2" />
        </svg>
        <span className="text-[11px] text-text-secondary">Projected</span>
      </div>
    </div>
  );

  return (
    <Card title="Cumulative Spend" action={legend} className="overflow-hidden">
      <div className="h-56">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData}>
            <defs>
              <linearGradient id="cumulativeFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--color-brand)" stopOpacity={0.15} />
                <stop offset="100%" stopColor="var(--color-brand)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="var(--color-border-subtle)"
              vertical={false}
            />
            <XAxis
              dataKey="date"
              tickFormatter={formatDate}
              interval={days <= 7 ? 0 : 4}
              tick={{ fill: "var(--color-text-tertiary)", fontSize: 11 }}
              axisLine={{ stroke: "var(--color-border)" }}
              tickLine={false}
            />
            <YAxis
              tickFormatter={(v) => `$${v}`}
              tick={{ fill: "var(--color-text-tertiary)", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              width={60}
            />
            <Tooltip content={<TrendTooltip />} />
            {/* Gradient fill under actual line */}
            <Area
              type="monotone"
              dataKey="cumulative"
              stroke="var(--color-brand)"
              strokeWidth={2}
              fill="url(#cumulativeFill)"
              dot={false}
              activeDot={{ r: 4, fill: "var(--color-brand)", strokeWidth: 0 }}
              name="Cumulative"
              connectNulls={false}
            />
            {/* Projected dashed line */}
            <Line
              type="monotone"
              dataKey="projected"
              stroke="var(--color-brand)"
              strokeWidth={1.5}
              strokeDasharray="6 4"
              dot={false}
              name="Projected"
              connectNulls={false}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}

// Custom tooltip matching SpendTooltip dark style
interface TrendTooltipProps {
  active?: boolean;
  payload?: Payload<number, string>[];
  label?: string;
}

function TrendTooltip({ active, payload, label }: TrendTooltipProps) {
  if (!active || !payload?.length || !label) return null;

  const dateLabel = new Date(label + "T00:00:00").toLocaleDateString("en-US", {
    weekday: "short",
    month: "short",
    day: "numeric",
  });

  return (
    <div className="rounded-lg border border-border bg-surface/95 p-3 shadow-lg backdrop-blur-sm">
      <p className="mb-2 border-b border-border-subtle pb-2 text-xs font-medium text-text">{dateLabel}</p>
      <div className="space-y-1">
        {payload.map((p: Payload<number, string>) => {
          if (p.value == null) return null;
          const isProjected = p.dataKey === "projected";
          return (
            <div
              key={String(p.dataKey)}
              className="flex items-center justify-between gap-6"
            >
              <div className="flex items-center gap-2">
                <span
                  className={cn(
                    "h-2 w-2 shrink-0 rounded-full",
                    isProjected
                      ? "border border-dashed border-brand"
                      : "bg-brand",
                  )}
                />
                <span className="text-xs text-text-secondary">
                  {isProjected ? "Projected" : "Cumulative"}
                </span>
              </div>
              <span className="font-mono text-xs font-semibold text-text">
                ${Number(p.value).toFixed(2)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
