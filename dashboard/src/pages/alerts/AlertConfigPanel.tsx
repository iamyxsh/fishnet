import { useState, useCallback } from "react";
import { ChevronDown } from "lucide-react";
import { Toggle } from "@/components/ui/Toggle";
import { cn } from "@/lib/cn";
import { useFetch } from "@/hooks/use-fetch";
import { fetchAlertConfig, updateAlertConfig } from "@/api/endpoints/alerts";
import { ALERT_TYPE_LABELS } from "@/lib/constants";
import type { AlertConfigToggles, AlertType } from "@/api/types";

const TOGGLE_DESCRIPTIONS: Record<keyof AlertConfigToggles, string> = {
  prompt_drift: "Alert when system prompt hash changes between requests",
  prompt_size: "Alert when prompt token count exceeds the configured limit",
  budget_warning: "Alert when spend approaches budget limit",
  budget_exceeded: "Alert when spend exceeds budget limit",
  onchain_denied: "Alert when an on-chain signing request is denied by policy",
  rate_limit_hit: "Alert when a service rate limit is reached",
};

const TOGGLE_ORDER: (keyof AlertConfigToggles)[] = [
  "prompt_drift",
  "prompt_size",
  "budget_warning",
  "budget_exceeded",
  "onchain_denied",
  "rate_limit_hit",
];

const DEFAULT_TOGGLES: AlertConfigToggles = {
  prompt_drift: true,
  prompt_size: true,
  budget_warning: true,
  budget_exceeded: true,
  onchain_denied: true,
  rate_limit_hit: true,
};

export function AlertConfigPanel() {
  const { data: config, loading } = useFetch(fetchAlertConfig);
  const [open, setOpen] = useState(false);

  const [localToggles, setLocalToggles] = useState<AlertConfigToggles | null>(
    null,
  );
  const [localRetention, setLocalRetention] = useState<number | null>(null);

  const toggles = localToggles ?? config?.toggles ?? DEFAULT_TOGGLES;
  const retention = localRetention ?? config?.retention_days ?? 30;

  // Count how many toggles are enabled for the collapsed summary
  const enabledCount = TOGGLE_ORDER.filter((k) => toggles[k]).length;

  const handleToggle = useCallback(
    async (key: keyof AlertConfigToggles, value: boolean) => {
      const prev = { ...toggles };
      setLocalToggles({ ...prev, [key]: value });
      try {
        await updateAlertConfig({ [key]: value });
      } catch {
        setLocalToggles(prev);
      }
    },
    [toggles],
  );

  const handleRetentionSave = useCallback(async () => {
    const days = Math.max(1, Math.min(365, retention));
    setLocalRetention(days);
    try {
      await updateAlertConfig({ retention_days: days });
    } catch {
      setLocalRetention(config?.retention_days ?? 30);
    }
  }, [retention, config]);

  return (
    <div className="rounded-xl border border-border bg-surface">
      {/* Accordion header */}
      <button
        onClick={() => setOpen((prev) => !prev)}
        className="flex w-full items-center justify-between px-6 py-4"
      >
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-text">
            Alert Notifications
          </h3>
          <span className="text-xs text-text-tertiary">
            {enabledCount}/{TOGGLE_ORDER.length} enabled
          </span>
        </div>
        <ChevronDown
          size={16}
          className={cn(
            "text-text-tertiary transition-transform duration-200",
            open && "rotate-180",
          )}
        />
      </button>

      {/* Collapsible content */}
      <div
        className={cn(
          "grid transition-[grid-template-rows] duration-200",
          open ? "grid-rows-[1fr]" : "grid-rows-[0fr]",
        )}
      >
        <div className="overflow-hidden">
          <div className="space-y-4 border-t border-border px-6 py-6">
            {TOGGLE_ORDER.map((key) => (
              <div
                key={key}
                className="flex items-center justify-between gap-4"
              >
                <div className="min-w-0">
                  <p className="text-sm font-medium text-text">
                    {ALERT_TYPE_LABELS[key as AlertType]}
                  </p>
                  <p className="text-xs text-text-secondary">
                    {TOGGLE_DESCRIPTIONS[key]}
                  </p>
                </div>
                <Toggle
                  checked={toggles[key]}
                  onChange={(v) => handleToggle(key, v)}
                  disabled={loading}
                />
              </div>
            ))}

            <div className="border-t border-border" />

            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-medium text-text">
                  Retention Period
                </p>
                <p className="text-xs text-text-secondary">
                  Number of days to keep alert history (1–365)
                </p>
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={retention}
                  onChange={(e) => setLocalRetention(Number(e.target.value))}
                  onBlur={handleRetentionSave}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") handleRetentionSave();
                  }}
                  className="w-20 rounded-lg border border-border bg-surface px-3 py-1.5 text-right text-sm tabular-nums text-text transition-colors focus:border-brand focus:outline-none"
                />
                <span className="text-xs text-text-secondary">days</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
