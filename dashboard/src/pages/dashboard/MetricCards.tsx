import { Link } from "react-router-dom";
import { StatCard } from "@/components/ui/StatCard";
import { Zap, DollarSign, Activity, AlertTriangle } from "lucide-react";
import { formatCurrency } from "@/lib/format";
import { ROUTES } from "@/lib/constants";
import type { StatusResponse, SpendResponse } from "@/api/types";

interface MetricCardsProps {
  status: StatusResponse;
  spend: SpendResponse | null;
  activeAlerts: number;
}

export function MetricCards({ status, spend, activeAlerts }: MetricCardsProps) {
  const totalSpent = spend?.total_spent_cents ?? 0;
  const totalBudget = spend?.total_budget_cents ?? 0;
  const spendPct = totalBudget > 0 ? (totalSpent / totalBudget) * 100 : 0;

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
      <StatCard
        label="Today's Spend"
        value={formatCurrency(totalSpent)}
        icon={<DollarSign size={18} />}
        accentColor="bg-brand"
        progress={{
          value: spendPct,
          color: spendPct > 90 ? "bg-danger" : spendPct > 70 ? "bg-warning" : "bg-brand",
        }}
        subtitle={`${formatCurrency(totalBudget)} limit`}
      />

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
