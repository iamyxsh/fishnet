import { useState, useCallback, useMemo } from "react";
import { useFetch } from "./use-fetch";
import { fetchAlerts, dismissAlert } from "@/api/endpoints/alerts";
import { POLLING_INTERVALS } from "@/lib/constants";
import type { Alert } from "@/api/types";

interface UseAlertsReturn {
  /** All alerts (includes dismissed) */
  alerts: Alert[];
  /** Only undismissed alerts, sorted newest-first */
  undismissed: Alert[];
  /** Latest undismissed alert (for dashboard banner) */
  latest: Alert | null;
  loading: boolean;
  error: Error | null;
  /** Dismiss a single alert by ID (optimistic) */
  dismiss: (id: string) => Promise<void>;
  /** Dismiss multiple alerts in parallel (optimistic) */
  dismissBulk: (ids: string[]) => Promise<void>;
  refetch: () => void;
}

export function useAlerts(): UseAlertsReturn {
  const { data, loading, error, refetch } = useFetch(fetchAlerts, {
    pollInterval: POLLING_INTERVALS.ALERTS,
  });

  // Local override for optimistic dismissals
  const [optimisticDismissed, setOptimisticDismissed] = useState<Set<string>>(
    new Set(),
  );

  const alerts = useMemo(() => {
    if (!data) return [];
    return data.alerts.map((a) =>
      optimisticDismissed.has(a.id) ? { ...a, dismissed: true } : a,
    );
  }, [data, optimisticDismissed]);

  const undismissed = useMemo(
    () =>
      alerts
        .filter((a) => !a.dismissed)
        .sort((a, b) => b.timestamp - a.timestamp),
    [alerts],
  );

  const latest = undismissed[0] ?? null;

  const dismiss = useCallback(
    async (id: string) => {
      // Optimistic update
      setOptimisticDismissed((prev) => new Set(prev).add(id));
      try {
        await dismissAlert(id);
      } catch {
        // Rollback on failure
        setOptimisticDismissed((prev) => {
          const next = new Set(prev);
          next.delete(id);
          return next;
        });
      }
    },
    [],
  );

  const dismissBulk = useCallback(
    async (ids: string[]) => {
      // Optimistic update all at once
      setOptimisticDismissed((prev) => {
        const next = new Set(prev);
        for (const id of ids) next.add(id);
        return next;
      });

      const results = await Promise.allSettled(ids.map((id) => dismissAlert(id)));

      // Rollback only the failed ones
      const failed = ids.filter((_, i) => results[i].status === "rejected");
      if (failed.length > 0) {
        setOptimisticDismissed((prev) => {
          const next = new Set(prev);
          for (const id of failed) next.delete(id);
          return next;
        });
      }
    },
    [],
  );

  return {
    alerts,
    undismissed,
    latest,
    loading,
    error,
    dismiss,
    dismissBulk,
    refetch,
  };
}
