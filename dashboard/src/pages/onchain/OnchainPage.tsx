import { useCallback } from "react";
import { Shield, ShieldAlert } from "lucide-react";
import { useFetch } from "@/hooks/use-fetch";
import { POLLING_INTERVALS } from "@/lib/constants";
import {
  fetchSignerStatus,
  fetchOnchainConfig,
  updateOnchainConfig,
} from "@/api/endpoints/onchain";
import { Skeleton, SkeletonCard } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { SignerStatusCard } from "./SignerStatusCard";
import { OnchainStats } from "./OnchainStats";
import { WhitelistEditor } from "./WhitelistEditor";
import { PolicyLimitsSummary } from "./PolicyLimitsSummary";
import { PermitHistoryTable } from "./PermitHistoryTable";

export default function OnchainPage() {
  const {
    data: signer,
    loading: signerLoading,
  } = useFetch(fetchSignerStatus, {
    pollInterval: POLLING_INTERVALS.ONCHAIN,
  });

  const {
    data: config,
    loading: configLoading,
    refetch: refetchConfig,
  } = useFetch(fetchOnchainConfig);

  const handleWhitelistUpdate = useCallback(
    async (whitelist: Record<string, string[]>) => {
      await updateOnchainConfig({ whitelist });
      refetchConfig();
    },
    [refetchConfig],
  );

  const isLoading = (signerLoading && !signer) || (configLoading && !config);

  // Full skeleton loading state
  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-10 w-full rounded-xl" />
        <Skeleton className="h-20 w-full rounded-xl" />
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
          <SkeletonCard />
        </div>
        <Skeleton className="h-64 w-full rounded-xl" />
        <Skeleton className="h-48 w-full rounded-xl" />
        <Skeleton className="h-[400px] w-full rounded-xl" />
      </div>
    );
  }

  // Disabled state
  if (signer && !signer.enabled) {
    return (
      <EmptyState
        icon={<Shield size={24} className="text-text-tertiary" />}
        title="Onchain module disabled"
        subtitle="Enable the signer in your fishnet.toml configuration to start managing onchain permits."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* DEFAULT DENY banner */}
      <div className="animate-fade-in-up relative flex items-center gap-2.5 overflow-hidden rounded-xl border border-danger/20 bg-danger-dim px-4 py-2.5">
        {/* Subtle scan-line sweep */}
        <div className="banner-scan pointer-events-none absolute inset-0 w-1/3 bg-gradient-to-r from-transparent via-danger/[0.04] to-transparent" />
        <ShieldAlert size={16} className="shrink-0 text-danger" />
        <div>
          <span className="text-xs font-bold uppercase tracking-wider text-danger">
            Default Deny
          </span>
          <span className="ml-2 text-xs text-text-secondary">
            All transactions are blocked unless the target contract and function
            selector are explicitly whitelisted below.
          </span>
        </div>
      </div>

      {/* Signer status hero card */}
      {signer && (
        <div className="animate-fade-in-up" style={{ animationDelay: "80ms" }}>
          <SignerStatusCard status={signer} />
        </div>
      )}

      {/* Stats row */}
      {signer && config && (
        <div className="animate-fade-in-up" style={{ animationDelay: "160ms" }}>
          <OnchainStats
            stats={signer.stats}
            dailySpendCap={config.limits.daily_spend_cap_usd}
          />
        </div>
      )}

      {/* Whitelist editor */}
      {config && (
        <div className="animate-fade-in-up" style={{ animationDelay: "240ms" }}>
          <WhitelistEditor
            whitelist={config.whitelist}
            onUpdate={handleWhitelistUpdate}
          />
        </div>
      )}

      {/* Policy limits */}
      {config && (
        <div className="animate-fade-in-up" style={{ animationDelay: "300ms" }}>
          <PolicyLimitsSummary config={config} />
        </div>
      )}

      {/* Permit history table (self-contained data fetching) */}
      <div className="animate-fade-in-up" style={{ animationDelay: "360ms" }}>
        <PermitHistoryTable />
      </div>
    </div>
  );
}
