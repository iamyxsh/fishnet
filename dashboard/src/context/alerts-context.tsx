import { createContext, useContext } from "react";
import { useAlerts } from "@/hooks/use-alerts";
import type { Alert } from "@/api/types";

interface AlertsContextValue {
  alerts: Alert[];
  undismissed: Alert[];
  latest: Alert | null;
  loading: boolean;
  error: Error | null;
  dismiss: (id: string) => Promise<void>;
  dismissBulk: (ids: string[]) => Promise<void>;
  refetch: () => void;
}

const AlertsContext = createContext<AlertsContextValue | null>(null);

export function AlertsProvider({ children }: { children: React.ReactNode }) {
  const value = useAlerts();
  return (
    <AlertsContext.Provider value={value}>{children}</AlertsContext.Provider>
  );
}

export function useAlertsContext(): AlertsContextValue {
  const ctx = useContext(AlertsContext);
  if (!ctx) {
    throw new Error("useAlertsContext must be used within <AlertsProvider>");
  }
  return ctx;
}
