import { useMemo } from "react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from "recharts";
import { Card } from "@/components/ui/Card";
import { ServiceDot } from "@/components/ui/ServiceDot";
import { SERVICE_LABELS, SERVICE_CHART_COLORS } from "@/lib/constants";
import type { DailySpendEntry } from "@/api/types";
import type { SpendDays } from "@/api/endpoints/spend-analytics";
import { SpendTooltip } from "./SpendTooltip";

interface SpendBarChartProps {
  daily: DailySpendEntry[];
  services: string[];
  days: SpendDays;
}

export function SpendBarChart({ daily, services, days }: SpendBarChartProps) {
  // Pivot: one row per date, columns per service
  const chartData = useMemo(() => {
    const byDate = new Map<string, Record<string, number | string>>();

    for (const entry of daily) {
      if (!byDate.has(entry.date)) {
        byDate.set(entry.date, { date: entry.date });
      }
      const row = byDate.get(entry.date)!;
      row[entry.service] =
        ((row[entry.service] as number) ?? 0) + entry.cost_usd;
    }

    return Array.from(byDate.values()).sort((a, b) =>
      (a.date as string).localeCompare(b.date as string),
    );
  }, [daily]);

  const formatDate = (dateStr: string) => {
    const d = new Date(dateStr + "T00:00:00");
    return d.toLocaleDateString("en-US", { month: "short", day: "numeric" });
  };

  const tickInterval = days <= 7 ? 0 : days <= 14 ? 1 : 4;

  const legend = (
    <div className="flex items-center gap-4">
      {services.map((svc) => (
        <div key={svc} className="flex items-center gap-1.5">
          <ServiceDot service={svc} />
          <span className="text-[11px] text-text-tertiary">
            {SERVICE_LABELS[svc as keyof typeof SERVICE_LABELS] ?? svc}
          </span>
        </div>
      ))}
    </div>
  );

  return (
    <Card title="Daily Spend" action={legend} hover={false}>
      <div className="h-72">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} barCategoryGap="20%">
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="var(--color-border-subtle)"
              vertical={false}
            />
            <XAxis
              dataKey="date"
              tickFormatter={formatDate}
              interval={tickInterval}
              tick={{ fill: "var(--color-text-tertiary)", fontSize: 11 }}
              axisLine={{ stroke: "var(--color-border)" }}
              tickLine={false}
            />
            <YAxis
              tickFormatter={(v) => `$${v}`}
              tick={{ fill: "var(--color-text-tertiary)", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              width={50}
            />
            <Tooltip
              content={<SpendTooltip />}
              cursor={{ fill: "var(--color-surface-hover)", opacity: 0.5 }}
            />
            {services.map((svc, i) => (
              <Bar
                key={svc}
                dataKey={svc}
                stackId="spend"
                fill={SERVICE_CHART_COLORS[svc] ?? "#8B5CF6"}
                radius={
                  i === services.length - 1 ? [2, 2, 0, 0] : [0, 0, 0, 0]
                }
                name={
                  SERVICE_LABELS[svc as keyof typeof SERVICE_LABELS] ?? svc
                }
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
