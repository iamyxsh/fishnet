import { apiFetch } from "../client";
import type { SpendAnalyticsResponse } from "../types";

export function fetchSpend(): Promise<SpendAnalyticsResponse> {
  return apiFetch<SpendAnalyticsResponse>("/spend?days=1");
}
