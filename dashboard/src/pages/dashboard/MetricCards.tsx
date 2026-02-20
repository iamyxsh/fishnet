import { Link } from "react-router-dom";
import { StatCard } from "@/components/ui/StatCard";
import { Zap, DollarSign, Activity, AlertTriangle } from "lucide-react";
import { formatDollars } from "@/lib/format";
import { ROUTES } from "@/lib/constants";
import type { StatusResponse, SpendAnalyticsResponse } from "@/api/types";

interface MetricCardsProps {
  status: StatusResponse;
  spend: SpendAnalyticsResponse | null;
  activeAlerts: number;
}

export function MetricCards({ status, spend, activeAlerts }: MetricCardsProps) {
  const budgets = spend?.budgets ?? {};
  const totalSpent = Object.values(budgets).reduce((s, b) => s + b.spent_today, 0);
  const totalLimit = Object.values(budgets).reduce((s, b) => s + (b.daily_limit ?? 0), 0);
  const spendPct = totalLimit > 0 ? (totalSpent / totalLimit) * 100 : 0;

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
      {/* Total Requests */}
      <StatCard
        label="Total Requests"
        value={status.total_requests_24h.toLocaleString()}
        icon={<Zap size={18} />}
        trend={<span>↗ +12.3%</span>}
        accentColor="bg-brand"
      />

      {/* Today's Spend */}
      <Link to={ROUTES.SPEND} className="block">
        <StatCard
          label="Today's Spend"
          value={formatDollars(totalSpent)}
          icon={<DollarSign size={18} />}
          accentColor="bg-brand"
          progress={{
            value: spendPct,
            color: spendPct > 90 ? "bg-danger" : spendPct > 70 ? "bg-warning" : "bg-brand",
          }}
          subtitle={totalLimit > 0 ? `${formatDollars(totalLimit)} limit` : "No limits set"}
        />
      </Link>

      {/* Active Services */}
      <StatCard
        label="Active Services"
        value={status.active_credentials}
        icon={<Activity size={18} />}
        trend={
          <span className="flex items-center gap-1 text-success">
            ↗ All healthy
          </span>
        }
        accentColor="bg-brand"
      />

      {/* Active Alerts — links to /alerts */}
      <Link to={ROUTES.ALERTS} className="block">
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
          accentColor={activeAlerts > 0 ? "bg-warning" : "bg-brand"}
        />
      </Link>
    </div>
  );
}
