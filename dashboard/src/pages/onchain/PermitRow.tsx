import { useState, useCallback } from "react";
import {
  CheckCircle2,
  XCircle,
  ChevronDown,
  AlertTriangle,
  Copy,
  Check,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { truncateAddress, truncateHash, timeAgoUnix, formatTimestamp, formatDollars } from "@/lib/format";
import { CHAIN_LABELS } from "@/lib/constants";
import { Identicon } from "./SignerStatusCard";
import type { Permit } from "@/api/types";

interface PermitRowProps {
  permit: Permit;
  isExpanded: boolean;
  onToggleExpand: () => void;
}

export function PermitRow({
  permit,
  isExpanded,
  onToggleExpand,
}: PermitRowProps) {
  const [copiedHash, setCopiedHash] = useState(false);
  const isDenied = permit.status === "denied";
  const hasReason = isDenied && !!permit.reason;

  const handleCopyHash = useCallback(() => {
    if (!permit.permit_hash) return;
    navigator.clipboard.writeText(permit.permit_hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 1500);
  }, [permit.permit_hash]);

  return (
    <>
      <tr
        className={cn(
          "group border-b border-border-subtle transition-colors duration-150",
          isDenied
            ? "border-l-2 border-l-danger/30 hover:bg-danger-dim/20"
            : "border-l-2 border-l-success/30 hover:bg-surface-hover",
          isExpanded && isDenied && "bg-danger-dim/10",
        )}
      >
        {/* Status icon */}
        <td className="py-3 pl-5 pr-0">
          {isDenied ? (
            <XCircle size={15} className="text-danger" />
          ) : (
            <CheckCircle2 size={15} className="text-success" />
          )}
        </td>

        {/* Time */}
        <td className="py-3 pr-3">
          <span
            className="text-xs tabular-nums text-text-tertiary"
            title={formatTimestamp(permit.created_at)}
          >
            {timeAgoUnix(permit.created_at)}
          </span>
        </td>

        {/* Target contract */}
        <td className="py-3 pr-3">
          <div className="flex items-center gap-2">
            <Identicon address={permit.target} size={16} />
            <code className="font-mono text-xs text-text">
              {truncateAddress(permit.target, 6)}
            </code>
          </div>
        </td>

        {/* Value */}
        <td className="py-3 pr-3">
          <span className="font-mono text-xs text-text">
            {formatDollars(permit.cost_usd)}
          </span>
        </td>

        {/* Chain */}
        <td className="py-3 pr-3">
          <span className="rounded-full bg-bg-tertiary px-2 py-0.5 font-mono text-[10px] text-text-secondary">
            {CHAIN_LABELS[permit.chain_id] ?? permit.chain_id}
          </span>
        </td>

        {/* Result badge */}
        <td className="py-3 pr-3">
          <span
            className={cn(
              "inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
              isDenied
                ? "bg-danger/15 text-danger"
                : "bg-success/15 text-success",
            )}
          >
            {permit.status === "approved" ? "Signed" : "Denied"}
          </span>
        </td>

        {/* Hash */}
        <td className="py-3 pr-3">
          {permit.permit_hash ? (
            <button
              onClick={handleCopyHash}
              className="group/hash flex items-center gap-1 transition-colors hover:text-brand"
            >
              <code className="font-mono text-xs text-text-tertiary transition-colors group-hover/hash:text-brand">
                {truncateHash(permit.permit_hash, 4)}
              </code>
              {copiedHash ? (
                <Check size={10} className="text-success" />
              ) : (
                <Copy
                  size={10}
                  className="text-text-tertiary opacity-0 transition-opacity group-hover/hash:opacity-100"
                />
              )}
            </button>
          ) : (
            <span className="text-xs text-text-tertiary">—</span>
          )}
        </td>

        {/* Expand chevron (denied only) */}
        <td className="py-3 pr-5">
          {hasReason ? (
            <button
              onClick={onToggleExpand}
              className="rounded-md p-0.5 text-text-tertiary transition-all duration-150 hover:bg-surface-hover hover:text-text"
            >
              <ChevronDown
                size={14}
                className={cn(
                  "transition-transform duration-200",
                  isExpanded && "rotate-180",
                )}
              />
            </button>
          ) : null}
        </td>
      </tr>

      {/* Expanded denial reason */}
      {isExpanded && hasReason && (
        <tr className="animate-fade-in-up border-b border-border-subtle border-l-2 border-l-danger/40 bg-danger-dim/20">
          <td colSpan={8} className="px-8 py-3">
            <div className="flex items-start gap-2">
              <AlertTriangle size={13} className="mt-0.5 shrink-0 text-danger" />
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-wider text-danger">
                  Denial Reason
                </p>
                <p className="mt-0.5 font-mono text-xs text-text-secondary">
                  {permit.reason}
                </p>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
