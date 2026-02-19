import { cn } from "@/lib/cn";
import { SERVICE_DOT_CLASSES } from "@/lib/constants";

interface ServiceDotProps {
  service: string;
  className?: string;
}

/** 8px colored dot identifying a service, with optional glow */
export function ServiceDot({ service, className }: ServiceDotProps) {
  return (
    <span
      className={cn(
        "h-2 w-2 shrink-0 rounded-full",
        SERVICE_DOT_CLASSES[service] ?? "bg-text-tertiary",
        className,
      )}
    />
  );
}
