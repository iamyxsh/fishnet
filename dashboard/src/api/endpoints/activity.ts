import { apiFetch } from "../client";
import type { RecentActivityResponse } from "../types";

export function fetchRecentActivity() {
  return apiFetch<RecentActivityResponse>("/activity");
}
