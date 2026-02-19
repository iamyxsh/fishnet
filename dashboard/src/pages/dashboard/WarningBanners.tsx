import { useState } from "react";
import { AlertTriangle, XCircle } from "lucide-react";
import { cn } from "@/lib/cn";
import { timeAgo } from "@/lib/format";
import type { Warning } from "@/api/types";

interface WarningBannersProps {
  warnings: Warning[];
}

export function WarningBanners({ warnings }: WarningBannersProps) {
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());

  const visible = warnings.filter((w) => !dismissed.has(w.id));
  if (visible.length === 0) return null;

  return (
    <div className="space-y-2">
      {visible.map((w, i) => {
        const isCritical = w.level === "critical";

        return (
          <div
            key={w.id}
            className={cn(
              "animate-fade-in-up flex items-start gap-3 rounded-xl border px-5 py-4",
              "transition-all duration-200",
              isCritical
                ? "border-danger/20 bg-danger-dim danger-glow"
                : "border-warning/20 bg-warning-dim warning-glow",
            )}
            style={{ animationDelay: `${i * 60}ms` }}
          >
            {/* Icon */}
            {isCritical ? (
              <XCircle size={18} className="mt-0.5 shrink-0 text-danger" />
            ) : (
              <AlertTriangle size={18} className="mt-0.5 shrink-0 text-warning" />
            )}

            {/* Content */}
            <div className="flex-1 min-w-0">
              <p
                className={cn(
                  "text-sm font-medium",
                  isCritical ? "text-danger" : "text-warning",
                )}
              >
                {w.message}
              </p>
              <p className="mt-0.5 text-xs text-text-tertiary">
                {w.ongoing ? "Ongoing" : timeAgo(w.timestamp)}
              </p>
            </div>

            {/* Dismiss */}
            <button
              onClick={() => setDismissed((prev) => new Set(prev).add(w.id))}
              className={cn(
                "shrink-0 rounded-md px-2 py-0.5 text-xs font-medium transition-all duration-150",
                "text-text-tertiary hover:text-text",
                isCritical
                  ? "hover:bg-danger/10"
                  : "hover:bg-warning/10",
              )}
            >
              Dismiss
            </button>
          </div>
        );
      })}
    </div>
  );
}
