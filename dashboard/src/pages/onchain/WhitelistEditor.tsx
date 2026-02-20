import { useState, useCallback } from "react";
import { Plus, ShieldAlert, ShieldX } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { EmptyState } from "@/components/ui/EmptyState";
import { WhitelistRow } from "./WhitelistRow";

interface WhitelistEditorProps {
  whitelist: Record<string, string[]>;
  onUpdate: (wl: Record<string, string[]>) => Promise<void>;
}

const ETH_ADDR_RE = /^0x[0-9a-fA-F]{40}$/;

export function WhitelistEditor({
  whitelist,
  onUpdate,
}: WhitelistEditorProps) {
  const [expandedAddr, setExpandedAddr] = useState<string | null>(null);
  const [editingAddr, setEditingAddr] = useState<string | null>(null);
  const [addingNew, setAddingNew] = useState(false);
  const [saving, setSaving] = useState(false);

  // Inline add form state
  const [newAddr, setNewAddr] = useState("");
  const [newSelectors, setNewSelectors] = useState("");
  const [addError, setAddError] = useState<string | null>(null);

  const entries = Object.entries(whitelist);

  const doUpdate = useCallback(
    async (updated: Record<string, string[]>) => {
      setSaving(true);
      try {
        await onUpdate(updated);
      } finally {
        setSaving(false);
      }
    },
    [onUpdate],
  );

  const handleAdd = useCallback(async () => {
    const addr = newAddr.trim().toLowerCase();
    if (!ETH_ADDR_RE.test(addr)) {
      setAddError("Invalid address — must be 0x + 40 hex characters");
      return;
    }
    if (whitelist[addr]) {
      setAddError("Address already in whitelist");
      return;
    }
    const selectors = newSelectors
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (selectors.length === 0) {
      setAddError("Add at least one function selector");
      return;
    }
    setAddError(null);
    const updated = { ...whitelist, [addr]: selectors };
    await doUpdate(updated);
    setAddingNew(false);
    setNewAddr("");
    setNewSelectors("");
  }, [newAddr, newSelectors, whitelist, doUpdate]);

  const handleRemove = useCallback(
    async (addr: string) => {
      const updated = { ...whitelist };
      delete updated[addr];
      await doUpdate(updated);
      if (expandedAddr === addr) setExpandedAddr(null);
      if (editingAddr === addr) setEditingAddr(null);
    },
    [whitelist, expandedAddr, editingAddr, doUpdate],
  );

  const handleSaveSelectors = useCallback(
    async (addr: string, selectors: string[]) => {
      const updated = { ...whitelist, [addr]: selectors };
      await doUpdate(updated);
      setEditingAddr(null);
    },
    [whitelist, doUpdate],
  );

  return (
    <div className={saving ? "pointer-events-none opacity-60 transition-opacity" : "transition-opacity"}>
      <Card
        padding={false}
        hover={false}
        title={
          <span className="flex items-center gap-2">
            Contract Whitelist
            {entries.length > 0 && (
              <span className="rounded-full bg-bg-tertiary px-2 py-0.5 font-mono text-[11px] font-medium text-text-secondary">
                {entries.length}
              </span>
            )}
          </span>
        }
        action={
          <div className="flex items-center gap-3">
            {/* DEFAULT DENY badge */}
            <div className="badge-glow flex items-center gap-1.5 rounded-md border border-danger/20 bg-danger-dim px-2.5 py-1">
              <ShieldAlert size={12} className="text-danger" />
              <span className="text-[10px] font-bold uppercase tracking-wider text-danger">
                Default Deny
              </span>
            </div>

            <button
              onClick={() => {
                setAddingNew(true);
                setAddError(null);
                setNewAddr("");
                setNewSelectors("");
              }}
              disabled={addingNew}
              className="flex items-center gap-1.5 rounded-lg bg-brand px-3 py-1.5 text-xs font-medium text-white transition-all duration-150 hover:bg-brand-hover disabled:opacity-40"
            >
              <Plus size={13} />
              Add Contract
            </button>
          </div>
        }
      >
        {/* Inline add form */}
        {addingNew && (
          <div className="border-b border-border border-l-2 border-l-brand bg-bg-secondary/50 px-6 py-4">
            <div className="space-y-3">
              <div>
                <label className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary">
                  Contract Address
                </label>
                <input
                  type="text"
                  value={newAddr}
                  onChange={(e) => {
                    setNewAddr(e.target.value);
                    setAddError(null);
                  }}
                  placeholder="0x0000000000000000000000000000000000000000"
                  className="mt-1 w-full rounded-lg border border-border bg-surface-input px-3 py-2 font-mono text-xs text-text placeholder:text-text-tertiary/40 focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
                />
              </div>
              <div>
                <label className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary">
                  Function Selectors{" "}
                  <span className="normal-case tracking-normal text-text-tertiary/60">
                    (one per line or comma-separated)
                  </span>
                </label>
                <textarea
                  value={newSelectors}
                  onChange={(e) => {
                    setNewSelectors(e.target.value);
                    setAddError(null);
                  }}
                  placeholder={"transfer(address,uint256)\napprove(address,uint256)\n0xa9059cbb"}
                  rows={3}
                  className="mt-1 w-full resize-none rounded-lg border border-border bg-surface-input px-3 py-2 font-mono text-xs text-text placeholder:text-text-tertiary/40 focus:border-brand/50 focus:outline-none focus:ring-1 focus:ring-brand/20"
                />
              </div>
              {addError && (
                <p className="text-xs text-danger">{addError}</p>
              )}
              <div className="flex items-center gap-2">
                <button
                  onClick={handleAdd}
                  disabled={saving}
                  className="rounded-lg bg-brand px-3 py-1.5 text-xs font-medium text-white transition-all duration-150 hover:bg-brand-hover disabled:opacity-40"
                >
                  {saving ? "Saving…" : "Add to Whitelist"}
                </button>
                <button
                  onClick={() => setAddingNew(false)}
                  className="rounded-lg px-3 py-1.5 text-xs text-text-tertiary transition-colors hover:bg-surface-hover hover:text-text"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Whitelist table */}
        {entries.length === 0 && !addingNew ? (
          <EmptyState
            icon={<ShieldX size={24} className="text-text-tertiary" />}
            title="No contracts whitelisted"
            subtitle="All onchain transactions will be denied. Add a contract to get started."
          />
        ) : entries.length > 0 ? (
          <div className="max-h-[400px] overflow-y-auto">
            <table className="w-full table-fixed">
              <colgroup>
                <col />
                <col className="w-[40%]" />
                <col className="w-28" />
                <col className="w-10" />
              </colgroup>
              <thead className="sticky top-0 z-10 bg-surface/80 backdrop-blur-sm">
                <tr className="border-b border-border">
                  <th className="py-3 pl-5 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Contract
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Allowed Functions
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary" />
                  <th className="py-3 pr-5" />
                </tr>
              </thead>
              <tbody>
                {entries.map(([addr, sels]) => (
                  <WhitelistRow
                    key={addr}
                    address={addr}
                    selectors={sels}
                    isExpanded={expandedAddr === addr}
                    isEditing={editingAddr === addr}
                    onToggleExpand={() =>
                      setExpandedAddr((prev) =>
                        prev === addr ? null : addr,
                      )
                    }
                    onEdit={() => {
                      setEditingAddr(addr);
                      setExpandedAddr(addr);
                    }}
                    onRemove={() => handleRemove(addr)}
                    onSave={(newSels) => handleSaveSelectors(addr, newSels)}
                    onCancelEdit={() => setEditingAddr(null)}
                  />
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>
    </div>
  );
}
