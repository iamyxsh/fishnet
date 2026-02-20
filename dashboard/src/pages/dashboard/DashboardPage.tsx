import { useFetch } from "@/hooks/use-fetch";
import { useAlertsContext } from "@/context/alerts-context";
import { fetchSpend } from "@/api/endpoints/spend";
import { SkeletonCard } from "@/components/ui/Skeleton";
import { MetricCards } from "./MetricCards";
import { AlertBanner } from "./AlertBanner";
import { SpendByService } from "./SpendByService";

export default function DashboardPage() {
  const { data: spend, loading: spendLoading } = useFetch(fetchSpend);
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
      {spendLoading || !spend ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
      ) : (
        <MetricCards spend={spend} activeAlerts={undismissed.length} />
      )}

      {/* Latest alert banner */}
      {latest && (
        <AlertBanner
          alert={latest}
          totalActive={undismissed.length}
          onDismiss={dismiss}
        />
      )}

      {/* Spend by Service */}
      {spendLoading || !spend ? (
        <SkeletonCard />
      ) : (
        <SpendByService spend={spend} />
      )}
    </div>
  );
}
