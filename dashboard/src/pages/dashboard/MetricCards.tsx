import { Link } from "react-router-dom";
import { StatCard } from "@/components/ui/StatCard";
import { Zap, DollarSign, Activity, AlertTriangle } from "lucide-react";
import { formatDollars } from "@/lib/format";
import { ROUTES } from "@/lib/constants";
import type { SpendAnalyticsResponse } from "@/api/types";

interface MetricCardsProps {
  spend: SpendAnalyticsResponse;
  activeAlerts: number;
}

export function MetricCards({ spend, activeAlerts }: MetricCardsProps) {
  const budgets = spend.budgets ?? {};
  const totalSpent = Object.values(budgets).reduce((s, b) => s + b.spent_today, 0);
  const totalLimit = Object.values(budgets).reduce((s, b) => s + (b.daily_limit ?? 0), 0);
  const spendPct = totalLimit > 0 ? (totalSpent / totalLimit) * 100 : 0;

  // Derive request count from spend daily data
  const totalRequests = spend.daily.reduce((s, d) => s + d.request_count, 0);

  // Derive active service count from budgets
  const activeServices = Object.keys(budgets).length;

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
      {/* Total Requests */}
      <div className="animate-fade-in-up h-full" style={{ animationDelay: "0ms" }}>
        <StatCard
          label="Total Requests"
          value={totalRequests.toLocaleString()}
          icon={<Zap size={18} />}
          accentColor="bg-brand"
        />
      </div>

      {/* Today's Spend */}
      <Link to={ROUTES.SPEND} className="animate-fade-in-up block h-full" style={{ animationDelay: "80ms" }}>
        <StatCard
          label="Today's Spend"
          value={formatDollars(totalSpent)}
          icon={<DollarSign size={18} />}
          accentColor="bg-success"
          progress={{
            value: spendPct,
            color: spendPct > 90 ? "bg-danger" : spendPct > 70 ? "bg-warning" : "bg-success",
          }}
          subtitle={totalLimit > 0 ? `${formatDollars(totalLimit)} limit` : "No limits set"}
        />
      </Link>

      {/* Active Services */}
      <div className="animate-fade-in-up h-full" style={{ animationDelay: "160ms" }}>
        <StatCard
          label="Active Services"
          value={activeServices}
          icon={<Activity size={18} />}
          accentColor="bg-info"
        />
      </div>

      {/* Active Alerts — links to /alerts */}
      <Link to={ROUTES.ALERTS} className="animate-fade-in-up block h-full" style={{ animationDelay: "240ms" }}>
        <StatCard
          label="Active Alerts"
          value={activeAlerts}
          icon={<AlertTriangle size={18} />}
          trend={
            activeAlerts > 0 ? (
              <span className="text-warning">
                {activeAlerts} warning{activeAlerts !== 1 ? "s" : ""}
              </span>
            ) : (
              <span className="text-success">All clear</span>
            )
          }
          accentColor={activeAlerts > 0 ? "bg-warning" : "bg-success"}
        />
      </Link>
    </div>
  );
}
