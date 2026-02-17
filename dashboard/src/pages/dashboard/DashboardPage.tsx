import { useFetch } from "@/hooks/use-fetch";
import { fetchStatus } from "@/api/endpoints/status";
import { fetchSpend } from "@/api/endpoints/spend";
import { fetchRecentActivity } from "@/api/endpoints/activity";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { MetricCards } from "./MetricCards";
import { WarningBanners } from "./WarningBanners";
import { SpendByService } from "./SpendByService";
import { RecentActivityTable } from "./RecentActivityTable";

export default function DashboardPage() {
  const { data: status, loading: statusLoading } = useFetch(fetchStatus);
  const { data: spend, loading: spendLoading } = useFetch(fetchSpend);
  const { data: activity, loading: activityLoading } = useFetch(fetchRecentActivity);

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
        <MetricCards status={status} spend={spend} />
      )}

      {/* Warning banners */}
      {status && status.warnings.length > 0 && (
        <WarningBanners warnings={status.warnings} />
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
