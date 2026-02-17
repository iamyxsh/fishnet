import { apiFetch } from "../client";
import type { StatusResponse } from "../types";

export function fetchStatus() {
  return apiFetch<StatusResponse>("/status");
}
