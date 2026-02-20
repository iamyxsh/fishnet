import { useFetch } from "@/hooks/use-fetch";
import { useAlertsContext } from "@/context/alerts-context";
import { fetchStatus } from "@/api/endpoints/status";
import { fetchSpend } from "@/api/endpoints/spend";
import { fetchRecentActivity } from "@/api/endpoints/activity";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { MetricCards } from "./MetricCards";
import { AlertBanner } from "./AlertBanner";
import { SpendByService } from "./SpendByService";
import { RecentActivityTable } from "./RecentActivityTable";

export default function DashboardPage() {
  const { data: status, loading: statusLoading } = useFetch(fetchStatus);
  const { data: spend, loading: spendLoading } = useFetch(fetchSpend);
  const { data: activity, loading: activityLoading } = useFetch(fetchRecentActivity);
  const { latest, undismissed, dismiss } = useAlertsContext();

  return (
    <div className="space-y-6">
      {/* Monitoring subtitle with subtle code styling */}
      <p className="text-sm text-text-secondary">
        Monitoring proxy activity on{" "}
        <code className="rounded-md bg-bg-tertiary/50 px-1.5 py-0.5 font-mono text-xs text-text">
          localhost:8472
        </code>
      </p>

      {/* Metric cards row */}
      {statusLoading || !status ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (
        <MetricCards
          status={status}
          spend={spend}
          activeAlerts={undismissed.length}
        />
      )}

      {/* Latest alert banner */}
      {latest && (
        <AlertBanner
          alert={latest}
          totalActive={undismissed.length}
          onDismiss={dismiss}
        />
      )}

      {/* Two-column: Spend by Service + Recent Activity */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {spendLoading || !spend ? (
          <SkeletonCard />
        ) : (
          <SpendByService spend={spend} />
        )}

        {activityLoading || !activity ? (
          <SkeletonCard />
        ) : (
          <RecentActivityTable activities={activity.activities} />
        )}
      </div>
    </div>
  );
}
