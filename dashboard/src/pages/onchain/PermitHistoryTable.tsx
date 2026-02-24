import { useState, useMemo, useCallback } from "react";
import { ChevronLeft, ChevronRight, FileText } from "lucide-react";
import { Card } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { useFetch } from "@/hooks/use-fetch";
import { fetchPermits, type PermitDays } from "@/api/endpoints/onchain";
import { POLLING_INTERVALS } from "@/lib/constants";
import type { PermitStatus } from "@/api/types";
import { PermitFilters } from "./PermitFilters";
import { PermitRow } from "./PermitRow";

const PAGE_SIZE = 25;

export function PermitHistoryTable() {
  const [days, setDays] = useState<PermitDays>(30);
  const [statusFilter, setStatusFilter] = useState<PermitStatus | "all">("all");
  const [page, setPage] = useState(0);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const apiStatus = statusFilter === "all" ? undefined : statusFilter;

  const { data, loading } = useFetch(
    () => fetchPermits(days, apiStatus),
    { deps: [days, apiStatus], pollInterval: POLLING_INTERVALS.ONCHAIN },
  );

  const permits = useMemo(() => {
    if (!data) return [];
    return [...data.permits].sort((a, b) => b.created_at - a.created_at);
  }, [data]);

  const totalPages = Math.max(1, Math.ceil(permits.length / PAGE_SIZE));
  const paginatedPermits = useMemo(() => {
    const start = page * PAGE_SIZE;
    return permits.slice(start, start + PAGE_SIZE);
  }, [permits, page]);

  const hasNextPage = page < totalPages - 1;
  const hasPrevPage = page > 0;

  const handleDaysChange = useCallback((d: PermitDays) => {
    setDays(d);
    setPage(0);
    setExpandedId(null);
  }, []);

  const handleStatusChange = useCallback((s: PermitStatus | "all") => {
    setStatusFilter(s);
    setPage(0);
    setExpandedId(null);
  }, []);

  if (loading && !data) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-8 w-64 rounded-lg" />
        <Skeleton className="h-[400px] w-full rounded-xl" />
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Toolbar: total count + filters */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-text-secondary">
          <span className="font-mono text-base font-bold text-text">{permits.length}</span>{" "}
          permit{permits.length !== 1 ? "s" : ""} in {days}d
        </p>
        <PermitFilters
          days={days}
          statusFilter={statusFilter}
          onDaysChange={handleDaysChange}
          onStatusChange={handleStatusChange}
        />
      </div>

      {/* Table */}
      {permits.length === 0 ? (
        <EmptyState
          icon={<FileText size={24} className="text-text-tertiary" />}
          title="No permits found"
          subtitle="Permit history will appear once transactions flow through Fishnet."
        />
      ) : (
        <Card padding={false} hover={false}>
          <div className="max-h-[calc(100vh-480px)] overflow-y-auto">
            <table className="w-full table-fixed">
              <colgroup>
                <col className="w-8" />
                <col className="w-20" />
                <col />
                <col className="w-24" />
                <col className="w-24" />
                <col className="w-20" />
                <col className="w-28" />
                <col className="w-8" />
              </colgroup>
              <thead className="sticky top-0 z-10 bg-surface/80 backdrop-blur-sm">
                <tr className="border-b border-border">
                  <th className="py-3 pl-5 pr-0 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary" />
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Time
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Target
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Value
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Chain
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Result
                  </th>
                  <th className="py-3 pr-3 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-text-secondary">
                    Hash
                  </th>
                  <th className="py-3 pr-5" />
                </tr>
              </thead>
              <tbody>
                {paginatedPermits.map((permit) => (
                  <PermitRow
                    key={permit.id}
                    permit={permit}
                    isExpanded={expandedId === permit.id}
                    onToggleExpand={() =>
                      setExpandedId((prev) =>
                        prev === permit.id ? null : permit.id,
                      )
                    }
                  />
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination footer */}
          <div className="flex items-center justify-between border-t border-border px-5 py-3">
            <p className="text-xs tabular-nums text-text-tertiary">
              Showing {paginatedPermits.length} of {permits.length}
            </p>
            <div className="flex items-center gap-1.5">
              <button
                onClick={() => { setPage((p) => p - 1); setExpandedId(null); }}
                disabled={!hasPrevPage}
                className="flex items-center gap-0.5 rounded-md px-2 py-1 text-xs font-medium text-text-secondary transition-colors hover:bg-surface-hover disabled:pointer-events-none disabled:opacity-30"
              >
                <ChevronLeft size={14} />
                Prev
              </button>
              <span className="rounded-md bg-bg-tertiary px-2.5 py-0.5 font-mono text-xs tabular-nums text-text-secondary">
                {page + 1}
              </span>
              <button
                onClick={() => { setPage((p) => p + 1); setExpandedId(null); }}
                disabled={!hasNextPage}
                className="flex items-center gap-0.5 rounded-md px-2 py-1 text-xs font-medium text-text-secondary transition-colors hover:bg-surface-hover disabled:pointer-events-none disabled:opacity-30"
              >
                Next
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
