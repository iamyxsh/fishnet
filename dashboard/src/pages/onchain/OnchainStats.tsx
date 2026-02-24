import { CheckCircle2, XCircle, DollarSign, Clock } from "lucide-react";
import { StatCard } from "@/components/ui/StatCard";
import { formatDollars, timeAgoUnix } from "@/lib/format";
import type { SignerStats } from "@/api/types";

interface OnchainStatsProps {
  stats: SignerStats;
  dailySpendCap: number;
}

export function OnchainStats({ stats, dailySpendCap }: OnchainStatsProps) {
  const spendPct =
    dailySpendCap > 0
      ? (stats.spent_today_usd / dailySpendCap) * 100
      : 0;

  const cards = [
    {
      label: "Permits Signed",
      value: stats.total_permits_signed.toLocaleString(),
      icon: <CheckCircle2 size={18} />,
      accentColor: "bg-success",
    },
    {
      label: "Permits Denied",
      value: stats.total_permits_denied.toLocaleString(),
      icon: <XCircle size={18} />,
      accentColor: "bg-danger",
    },
    {
      label: "Spent Today",
      value: formatDollars(stats.spent_today_usd),
      icon: <DollarSign size={18} />,
      accentColor: "bg-brand",
      progress: dailySpendCap > 0
        ? {
            value: spendPct,
            color:
              spendPct > 90
                ? "bg-danger"
                : spendPct > 70
                  ? "bg-warning"
                  : "bg-brand",
          }
        : undefined,
      subtitle: dailySpendCap > 0
        ? `${formatDollars(dailySpendCap)} cap`
        : "No cap set",
    },
    {
      label: "Last Permit",
      value: stats.last_permit_at
        ? timeAgoUnix(stats.last_permit_at)
        : "Never",
      icon: <Clock size={18} />,
      accentColor: "bg-info",
    },
  ] as const;

  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-4">
      {cards.map((card, i) => (
        <div
          key={card.label}
          className="animate-fade-in-up h-full"
          style={{ animationDelay: `${i * 80}ms` }}
        >
          <StatCard
            label={card.label}
            value={card.value}
            icon={card.icon}
            accentColor={card.accentColor}
            progress={"progress" in card ? card.progress : undefined}
            subtitle={"subtitle" in card ? card.subtitle : undefined}
          />
        </div>
      ))}
    </div>
  );
}
