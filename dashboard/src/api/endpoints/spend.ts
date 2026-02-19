import { apiFetch } from "../client";
import type { SpendResponse } from "../types";

export function fetchSpend(period: "24h" | "7d" | "30d" = "24h") {
  return apiFetch<SpendResponse>(`/spend?period=${period}`);
}
