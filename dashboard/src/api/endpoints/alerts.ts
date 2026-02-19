import { apiFetch } from "../client";
import type { AlertsResponse, DismissAlertResponse } from "../types";

export function fetchAlerts(): Promise<AlertsResponse> {
  return apiFetch<AlertsResponse>("/alerts");
}

export function dismissAlert(id: string): Promise<DismissAlertResponse> {
  return apiFetch<DismissAlertResponse>("/alerts/dismiss", {
    method: "POST",
    body: JSON.stringify({ id }),
  });
}
