import { cn } from "@/lib/cn";

interface FilterPillProps {
  active: boolean;
  onClick: () => void;
  color?: "danger" | "warning";
  children: React.ReactNode;
}

export function FilterPill({ active, onClick, color, children }: FilterPillProps) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "rounded-full px-3 py-1 text-xs font-medium transition-all duration-150",
        active
          ? color === "danger"
            ? "bg-danger/15 text-danger"
            : color === "warning"
              ? "bg-warning/15 text-warning"
              : "bg-brand-muted text-brand"
          : "bg-surface text-text-tertiary hover:bg-surface-hover hover:text-text",
      )}
    >
      {children}
    </button>
  );
}
