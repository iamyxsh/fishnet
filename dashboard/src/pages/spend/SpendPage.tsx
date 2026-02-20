import { useState, useMemo } from "react";
import { BarChart3 } from "lucide-react";
import { useFetch } from "@/hooks/use-fetch";
import {
  fetchSpendAnalytics,
  type SpendDays,
} from "@/api/endpoints/spend-analytics";
import { POLLING_INTERVALS } from "@/lib/constants";
import { formatDollars } from "@/lib/format";
import { Skeleton } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { PeriodSelector } from "./PeriodSelector";
import { BudgetGauges } from "./BudgetGauges";
import { SpendBarChart } from "./SpendBarChart";
import { SpendTrendLine } from "./SpendTrendLine";

export default function SpendPage() {
  const [days, setDays] = useState<SpendDays>(30);

  const { data, loading } = useFetch(
    () => fetchSpendAnalytics(days),
    { deps: [days], pollInterval: POLLING_INTERVALS.SPEND },
  );

  const services = useMemo(() => {
    if (!data) return [];
    return [...new Set(data.daily.map((d) => d.service))];
  }, [data]);

  // Derived summary stats
  const summary = useMemo(() => {
    if (!data) return null;
    const totalSpend = data.daily.reduce((s, d) => s + d.cost_usd, 0);
    const uniqueDates = new Set(data.daily.map((d) => d.date));
    const numDays = uniqueDates.size || 1;
    const dailyAvg = totalSpend / numDays;
    return { totalSpend, dailyAvg, numDays };
  }, [data]);

  const isDisabled = data && !data.enabled;
  const isEmpty = data && data.enabled && data.daily.length === 0;

  if (loading && !data) {
    return (
      <div className="space-y-6">
        <div className="flex items-end justify-between">
          <Skeleton className="h-12 w-56 rounded-lg" />
          <Skeleton className="h-8 w-48 rounded-full" />
        </div>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5">
          {[...Array(3)].map((_, i) => (
            <Skeleton key={i} className="h-32 rounded-xl" />
          ))}
        </div>
        <Skeleton className="h-80 w-full rounded-xl" />
        <Skeleton className="h-64 w-full rounded-xl" />
      </div>
    );
  }

  if (isDisabled) {
    return (
      <EmptyState
        icon={<BarChart3 size={24} className="text-text-tertiary" />}
        title="Spend tracking disabled"
        subtitle="Enable track_spend in your Fishnet configuration to start recording spend data."
      />
    );
  }

  if (isEmpty) {
    return (
      <EmptyState
        icon={<BarChart3 size={24} className="text-text-tertiary" />}
        title="No activity recorded"
        subtitle="Spend data will appear once requests flow through Fishnet."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Summary header + period selector */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        {summary && (
          <div className="flex items-baseline gap-6">
            <div>
              <p className="text-[11px] font-medium uppercase tracking-wider text-text-tertiary">
                Total ({days}d)
              </p>
              <p className="font-mono text-2xl font-bold text-text">
                {formatDollars(summary.totalSpend)}
              </p>
            </div>
            <div>
              <p className="text-[11px] font-medium uppercase tracking-wider text-text-tertiary">
                Daily avg
              </p>
              <p className="font-mono text-lg font-semibold text-text-secondary">
                {formatDollars(summary.dailyAvg)}
              </p>
            </div>
          </div>
        )}
        <PeriodSelector days={days} onChange={setDays} />
      </div>

      {data && <BudgetGauges budgets={data.budgets} />}

      {data && (
        <SpendBarChart daily={data.daily} services={services} days={days} />
      )}

      {data && <SpendTrendLine daily={data.daily} days={days} />}
    </div>
  );
}
