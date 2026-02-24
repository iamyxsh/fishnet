import { apiFetch } from "../client";
import type { SpendAnalyticsResponse } from "../types";

export type SpendDays = 7 | 14 | 30;

export function fetchSpendAnalytics(
  days: SpendDays = 30,
): Promise<SpendAnalyticsResponse> {
  return apiFetch<SpendAnalyticsResponse>(`/spend?days=${days}`);
}
