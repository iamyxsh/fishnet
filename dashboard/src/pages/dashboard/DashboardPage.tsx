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
      {/* Monitoring status bar */}
      <div className="flex items-center gap-2 text-sm text-text-secondary">
        <span className="status-pulse inline-block h-2 w-2 rounded-full bg-success" />
        <span>
          Monitoring proxy on{" "}
          <code className="rounded-md bg-bg-tertiary/60 px-1.5 py-0.5 font-mono text-xs text-text">
            localhost:8472
          </code>
        </span>
      </div>

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
