import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

interface CardProps {
  title?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
  padding?: boolean;
  /** Enable hover lift effect (default: true) */
  hover?: boolean;
}

export function Card({
  title,
  action,
  children,
  className,
  padding = true,
  hover = true,
}: CardProps) {
  return (
    <div
      className={cn(
        "rounded-xl border border-border bg-surface",
        hover && "card-hover",
        className,
      )}
    >
      {(title || action) && (
        <div className="flex items-center justify-between border-b border-border px-6 py-4">
          {title && (
            <h3 className="text-sm font-semibold text-text">{title}</h3>
          )}
          {action && <div className="ml-auto">{action}</div>}
        </div>
      )}
      <div className={cn(padding && "p-6")}>{children}</div>
    </div>
  );
}
