import { useState, useCallback } from "react";
import { Copy, Check } from "lucide-react";
import { cn } from "@/lib/cn";
import { truncateAddress } from "@/lib/format";
import { CHAIN_LABELS } from "@/lib/constants";
import type { SignerStatusResponse } from "@/api/types";

interface SignerStatusCardProps {
  status: SignerStatusResponse;
}

/** Format signer mode string into a human-readable label */
function formatMode(mode: string | null): string {
  if (!mode) return "Not Configured";
  const map: Record<string, string> = {
    secure_enclave: "Secure Enclave",
    keyfile: "Keyfile",
    threshold: "Threshold (2-of-3)",
    "stub-secp256k1": "Local Signer",
  };
  return map[mode] ?? mode;
}

export function SignerStatusCard({ status }: SignerStatusCardProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = useCallback(() => {
    if (!status.address) return;
    navigator.clipboard.writeText(status.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [status.address]);

  const isActive = status.enabled && !!status.address;
  const modeLabel = formatMode(status.mode);

  return (
    <div className="animate-fade-in-up stat-card-glow relative overflow-hidden rounded-xl border border-border bg-surface">
      {/* Top accent line — green when active, brand when not */}
      <div className="absolute inset-x-0 top-0 h-[2px]">
        <div
          className={cn(
            "h-full w-full opacity-60",
            isActive ? "bg-success" : "bg-text-tertiary",
          )}
        />
        <div
          className={cn(
            "absolute inset-x-0 top-0 h-8 opacity-[0.04]",
            isActive ? "bg-success" : "bg-text-tertiary",
          )}
          style={{ filter: "blur(12px)" }}
        />
      </div>

      <div className="flex flex-wrap items-center gap-6 p-5 sm:gap-8">
        {/* Status indicator */}
        <div className="flex items-center gap-3">
          <span
            className={cn(
              "h-2.5 w-2.5 shrink-0 rounded-full",
              isActive
                ? "bg-success status-pulse"
                : status.enabled
                  ? "bg-danger"
                  : "bg-text-tertiary",
            )}
            style={isActive ? { boxShadow: "0 0 8px 3px rgba(34, 197, 94, 0.25)" } : undefined}
          />
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.06em] text-text-tertiary">
              Signer
            </p>
            <p
              className={cn(
                "text-base font-bold",
                isActive ? "text-success" : "text-text-secondary",
              )}
            >
              {isActive ? "Active" : status.enabled ? "Inactive" : "Not Configured"}
            </p>
          </div>
        </div>

        {/* Divider */}
        <div className="hidden h-10 w-px bg-border-subtle sm:block" />

        {/* Mode badge */}
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.06em] text-text-tertiary">
            Mode
          </p>
          <span className="mt-0.5 inline-block rounded-md border border-info/20 bg-info-dim px-2 py-0.5 text-xs font-medium text-info">
            {modeLabel}
          </span>
        </div>

        {/* Divider */}
        <div className="hidden h-10 w-px bg-border-subtle sm:block" />

        {/* Address with copy */}
        {status.address ? (
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.06em] text-text-tertiary">
              Address
            </p>
            <button
              onClick={handleCopy}
              className="group/copy mt-0.5 flex items-center gap-1.5 rounded-md px-1.5 py-0.5 transition-colors duration-150 hover:bg-surface-hover hover:text-brand"
            >
              <Identicon address={status.address} size={16} />
              <code className="font-mono text-sm text-text transition-colors duration-150 group-hover/copy:text-brand">
                {truncateAddress(status.address, 6)}
              </code>
              {copied ? (
                <Check size={12} className="text-success" />
              ) : (
                <Copy
                  size={12}
                  className="text-text-tertiary opacity-0 transition-opacity duration-150 group-hover/copy:opacity-100"
                />
              )}
            </button>
          </div>
        ) : (
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.06em] text-text-tertiary">
              Address
            </p>
            <p className="mt-0.5 text-xs text-text-tertiary">—</p>
          </div>
        )}

        {/* Divider */}
        {status.chain_ids.length > 0 && (
          <div className="hidden h-10 w-px bg-border-subtle sm:block" />
        )}

        {/* Chain IDs */}
        {status.chain_ids.length > 0 && (
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.06em] text-text-tertiary">
              Chains
            </p>
            <div className="mt-1 flex flex-wrap gap-1.5">
              {status.chain_ids.map((id) => (
                <span
                  key={id}
                  className="rounded-full bg-bg-tertiary px-2 py-0.5 font-mono text-[11px] text-text-secondary"
                >
                  {CHAIN_LABELS[id] ?? id}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/* ── Deterministic identicon ────────────────────── */

function hashCode(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

const IDENTICON_COLORS = [
  "#E63946", "#3B82F6", "#22C55E", "#F59E0B", "#8B5CF6",
  "#EC4899", "#06B6D4", "#F97316", "#14B8A6", "#A855F7",
];

export function Identicon({
  address,
  size = 18,
}: {
  address: string;
  size?: number;
}) {
  const h = hashCode(address.toLowerCase());
  const bg = IDENTICON_COLORS[h % IDENTICON_COLORS.length];
  const fg = IDENTICON_COLORS[(h * 7 + 3) % IDENTICON_COLORS.length];

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 18 18"
      className="shrink-0 rounded-[4px]"
      style={{ background: bg }}
    >
      {/* Simple deterministic pattern from address hash */}
      <rect x="3" y="3" width="4" height="4" rx="1" fill={fg} opacity={0.6} />
      <rect
        x="11"
        y="3"
        width="4"
        height="4"
        rx="1"
        fill={fg}
        opacity={(h % 3) * 0.2 + 0.3}
      />
      <rect
        x="3"
        y="11"
        width="4"
        height="4"
        rx="1"
        fill={fg}
        opacity={((h >> 4) % 3) * 0.2 + 0.3}
      />
      <rect x="11" y="11" width="4" height="4" rx="1" fill={fg} opacity={0.6} />
      <rect
        x="7"
        y="7"
        width="4"
        height="4"
        rx="1"
        fill={fg}
        opacity={((h >> 8) % 2) * 0.3 + 0.4}
      />
    </svg>
  );
}
