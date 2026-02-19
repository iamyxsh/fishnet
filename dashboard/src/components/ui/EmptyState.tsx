import type { ReactNode } from "react";

interface EmptyStateProps {
  icon: ReactNode;
  title: string;
  subtitle?: string;
}

export function EmptyState({ icon, title, subtitle }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-20">
      <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-surface-raised">
        {icon}
      </div>
      <p className="mt-4 text-sm font-medium text-text-secondary">{title}</p>
      {subtitle && (
        <p className="mt-1 text-xs text-text-tertiary">{subtitle}</p>
      )}
    </div>
  );
}
