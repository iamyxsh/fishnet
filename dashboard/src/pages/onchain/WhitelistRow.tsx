import { useState, useCallback } from "react";
import {
  ChevronDown,
  Pencil,
  Trash2,
  X,
  Plus,
  Check,
  Copy,
} from "lucide-react";
import { cn } from "@/lib/cn";
import { truncateAddress } from "@/lib/format";
import { Identicon } from "./SignerStatusCard";

interface WhitelistRowProps {
  address: string;
  selectors: string[];
  isExpanded: boolean;
  isEditing: boolean;
  onToggleExpand: () => void;
  onEdit: () => void;
  onRemove: () => void;
  onSave: (selectors: string[]) => void;
  onCancelEdit: () => void;
}

export function WhitelistRow({
  address,
  selectors,
  isExpanded,
  isEditing,
  onToggleExpand,
  onEdit,
  onRemove,
  onSave,
  onCancelEdit,
}: WhitelistRowProps) {
  const [copiedAddr, setCopiedAddr] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [editSelectors, setEditSelectors] = useState<string[]>(selectors);
  const [newSelector, setNewSelector] = useState("");

  const handleCopyAddr = useCallback(() => {
    navigator.clipboard.writeText(address);
    setCopiedAddr(true);
    setTimeout(() => setCopiedAddr(false), 1500);
  }, [address]);

  const handleRemoveSelector = useCallback((idx: number) => {
    setEditSelectors((prev) => prev.filter((_, i) => i !== idx));
  }, []);

  const handleAddSelector = useCallback(() => {
    const val = newSelector.trim();
    if (!val) return;
    setEditSelectors((prev) => [...prev, val]);
    setNewSelector("");
  }, [newSelector]);

  const handleSave = useCallback(() => {
    onSave(editSelectors.filter((s) => s.length > 0));
  }, [editSelectors, onSave]);

  const handleStartEdit = useCallback(() => {
    setEditSelectors(selectors);
    setNewSelector("");
    onEdit();
  }, [selectors, onEdit]);

  const handleCancelEdit = useCallback(() => {
    setEditSelectors(selectors);
    setNewSelector("");
    onCancelEdit();
  }, [selectors, onCancelEdit]);

  const handleConfirmRemove = useCallback(() => {
    setConfirming(false);
    onRemove();
  }, [onRemove]);

  const previewSelectors = selectors.slice(0, 3).join(", ");
  const remaining = selectors.length - 3;

  return (
    <>
      <tr
        className={cn(
          "group border-b border-border-subtle transition-colors duration-150",
          isExpanded ? "bg-surface-hover/30" : "hover:bg-surface-hover",
        )}
      >
        {/* Identicon + Address */}
        <td className="py-3 pl-5 pr-3">
          <div className="flex items-center gap-2.5">
            <Identicon address={address} size={20} />
            <button
              onClick={handleCopyAddr}
              className="group/addr flex items-center gap-1.5 transition-colors"
            >
              <code className="font-mono text-xs text-text transition-colors group-hover/addr:text-brand">
                {truncateAddress(address, 6)}
              </code>
              {copiedAddr ? (
                <Check size={10} className="text-success" />
              ) : (
                <Copy
                  size={10}
                  className="text-text-tertiary opacity-0 transition-opacity group-hover/addr:opacity-100"
                />
              )}
            </button>
          </div>
        </td>

        {/* Selectors preview */}
        <td className="py-3 pr-3">
          <span className="font-mono text-xs text-text-secondary">
            {previewSelectors}
            {remaining > 0 && (
              <span className="text-text-tertiary"> +{remaining}</span>
            )}
          </span>
        </td>

        {/* Actions */}
        <td className="py-3 pr-3">
          {confirming ? (
            <div className="flex items-center gap-2">
              <span className="text-[11px] text-danger">Remove?</span>
              <button
                onClick={handleConfirmRemove}
                className="rounded-md bg-danger/15 px-2 py-0.5 text-[11px] font-medium text-danger transition-colors hover:bg-danger/25"
              >
                Confirm
              </button>
              <button
                onClick={() => setConfirming(false)}
                className="rounded-md px-1.5 py-0.5 text-[11px] text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
              >
                Cancel
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
              <button
                onClick={handleStartEdit}
                className="rounded-md p-1 text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
                title="Edit selectors"
              >
                <Pencil size={13} />
              </button>
              <button
                onClick={() => setConfirming(true)}
                className="rounded-md p-1 text-text-tertiary transition-colors hover:bg-danger-dim hover:text-danger"
                title="Remove contract"
              >
                <Trash2 size={13} />
              </button>
            </div>
          )}
        </td>

        {/* Expand chevron */}
        <td className="py-3 pr-5">
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
        </td>
      </tr>

      {/* Expanded / Editing state */}
      {isExpanded && (
        <tr className="border-b border-border-subtle border-l-2 border-l-brand/40 bg-bg-secondary/50">
          <td colSpan={4} className="px-8 py-4">
            {/* Full address */}
            <div className="mb-3 flex items-center gap-2">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary">
                Full Address
              </span>
              <code className="rounded-md bg-bg-tertiary/60 px-2 py-0.5 font-mono text-[11px] text-text-secondary">
                {address}
              </code>
            </div>

            {/* Selectors list */}
            <div>
              <span className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary">
                Allowed Functions ({isEditing ? editSelectors.length : selectors.length})
              </span>

              <div className="mt-2 flex flex-wrap gap-2">
                {(isEditing ? editSelectors : selectors).map((sel, i) => (
                  <span
                    key={`${sel}-${i}`}
                    className={cn(
                      "inline-flex items-center gap-1.5 rounded-md border border-border-subtle bg-bg-tertiary/50 px-2 py-1 font-mono text-[11px] text-text-secondary transition-colors",
                      isEditing ? "pr-1" : "hover:border-border hover:bg-bg-tertiary",
                    )}
                  >
                    {sel}
                    {isEditing && (
                      <button
                        onClick={() => handleRemoveSelector(i)}
                        className="rounded p-0.5 text-text-tertiary transition-colors hover:bg-danger-dim hover:text-danger"
                      >
                        <X size={10} />
                      </button>
                    )}
                  </span>
                ))}
              </div>

              {/* Editing controls */}
              {isEditing && (
                <div className="mt-3 flex items-center gap-2">
                  <input
                    type="text"
                    value={newSelector}
                    onChange={(e) => setNewSelector(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleAddSelector()}
                    placeholder="0x12345678 or transfer(address,uint256)"
                    className="flex-1 rounded-lg border border-border bg-surface-input px-3 py-1.5 font-mono text-xs text-text placeholder:text-text-tertiary/50 focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
                  />
                  <button
                    onClick={handleAddSelector}
                    disabled={!newSelector.trim()}
                    className="flex items-center gap-1 rounded-lg bg-surface-hover px-2.5 py-1.5 text-xs font-medium text-text-secondary transition-colors hover:bg-bg-tertiary hover:text-text disabled:opacity-30"
                  >
                    <Plus size={12} />
                    Add
                  </button>
                </div>
              )}

              {isEditing && (
                <div className="mt-3 flex items-center gap-2 border-t border-border-subtle pt-3">
                  <button
                    onClick={handleSave}
                    disabled={editSelectors.length === 0}
                    className="rounded-lg bg-brand px-3 py-1.5 text-xs font-medium text-white transition-all duration-150 hover:bg-brand-hover disabled:opacity-40"
                  >
                    Save Changes
                  </button>
                  <button
                    onClick={handleCancelEdit}
                    className="rounded-lg px-3 py-1.5 text-xs text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
                  >
                    Cancel
                  </button>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
