import { apiFetch } from "../client";
import type {
  SignerStatusResponse,
  OnchainConfigResponse,
  OnchainConfigUpdatePayload,
  PermitStatus,
  PermitsResponse,
} from "../types";

export function fetchSignerStatus(): Promise<SignerStatusResponse> {
  return apiFetch<SignerStatusResponse>("/signer/status");
}

export function fetchOnchainConfig(): Promise<OnchainConfigResponse> {
  return apiFetch<OnchainConfigResponse>("/onchain/config");
}

export function updateOnchainConfig(
  payload: OnchainConfigUpdatePayload,
): Promise<OnchainConfigResponse> {
  return apiFetch<OnchainConfigResponse>("/onchain/config", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

export type PermitDays = 7 | 14 | 30;

export function fetchPermits(
  days: PermitDays = 30,
  status?: PermitStatus,
): Promise<PermitsResponse> {
  const params = new URLSearchParams({ days: String(days) });
  if (status) params.set("status", status);
  return apiFetch<PermitsResponse>(`/onchain/permits?${params.toString()}`);
}
