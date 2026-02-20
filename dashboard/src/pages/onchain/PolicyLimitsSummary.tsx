import { useState, useCallback } from "react";
import { Copy, Check } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { formatDollars, truncateAddress } from "@/lib/format";
import { Identicon } from "./SignerStatusCard";
import type { OnchainConfigResponse } from "@/api/types";

interface PolicyLimitsSummaryProps {
  config: OnchainConfigResponse;
}

function LimitItem({
  label,
  value,
  mono = true,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  const isDisabled = value === "Disabled";
  return (
    <div className="flex items-baseline justify-between gap-3 rounded-lg border border-border-subtle bg-bg-secondary/40 px-3.5 py-2.5 transition-colors hover:bg-bg-secondary/70">
      <span className="text-[11px] font-medium text-text-tertiary">{label}</span>
      <span
        className={`text-sm font-semibold ${mono ? "font-mono" : ""} ${isDisabled ? "text-text-tertiary" : "text-text"}`}
      >
        {value}
      </span>
    </div>
  );
}

export function PolicyLimitsSummary({ config }: PolicyLimitsSummaryProps) {
  const [copiedContract, setCopiedContract] = useState(false);
  const { limits, permits } = config;

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(permits.verifying_contract);
    setCopiedContract(true);
    setTimeout(() => setCopiedContract(false), 1500);
  }, [permits.verifying_contract]);

  return (
    <div>
      <Card
        title="Policy Limits"
        action={
          <span className="text-[10px] font-medium uppercase tracking-wider text-text-tertiary">
            Read-only
          </span>
        }
      >
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          <LimitItem
            label="Max Tx Value"
            value={
              limits.max_tx_value_usd > 0
                ? formatDollars(limits.max_tx_value_usd)
                : "Disabled"
            }
          />
          <LimitItem
            label="Daily Spend Cap"
            value={
              limits.daily_spend_cap_usd > 0
                ? formatDollars(limits.daily_spend_cap_usd)
                : "Disabled"
            }
          />
          <LimitItem
            label="Cooldown"
            value={
              limits.cooldown_seconds > 0
                ? `${limits.cooldown_seconds}s`
                : "Disabled"
            }
          />
          <LimitItem
            label="Max Slippage"
            value={
              limits.max_slippage_bps > 0
                ? `${limits.max_slippage_bps} bps`
                : "Disabled"
            }
          />
          <LimitItem
            label="Max Leverage"
            value={
              limits.max_leverage > 0 ? `${limits.max_leverage}x` : "Disabled"
            }
          />
          <LimitItem
            label="Permit Expiry"
            value={`${permits.expiry_seconds}s`}
          />
        </div>

        {/* Verifying contract */}
        {permits.verifying_contract && (
          <div className="mt-4 flex flex-wrap items-center gap-2 border-t border-border-subtle pt-4">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary">
              Verifying Contract
            </span>
            <button
              onClick={handleCopy}
              className="group/vc flex items-center gap-1.5 rounded-md px-1.5 py-0.5 transition-colors hover:bg-surface-hover"
            >
              <Identicon address={permits.verifying_contract} size={14} />
              <code className="font-mono text-xs text-text-secondary transition-colors group-hover/vc:text-brand">
                {truncateAddress(permits.verifying_contract, 8)}
              </code>
              {copiedContract ? (
                <Check size={10} className="text-success" />
              ) : (
                <Copy
                  size={10}
                  className="text-text-tertiary opacity-0 transition-opacity group-hover/vc:opacity-100"
                />
              )}
            </button>
            {permits.require_policy_hash && (
              <span className="rounded-md bg-info-dim px-1.5 py-0.5 text-[10px] font-medium text-info">
                Policy Hash Required
              </span>
            )}
          </div>
        )}

        {/* Configure link */}
        <p className="mt-3 text-[11px] text-text-tertiary">
          Configure limits in{" "}
          <code className="rounded bg-bg-tertiary/60 px-1 py-0.5 font-mono text-[10px]">
            fishnet.toml
          </code>
        </p>
      </Card>
    </div>
  );
}
