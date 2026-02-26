import { apiFetch } from "../client";
import type { CredentialsResponse, CreateCredentialPayload } from "../types";

export function fetchCredentials(): Promise<CredentialsResponse> {
  return apiFetch<CredentialsResponse>("/credentials");
}

export function createCredential(
  payload: CreateCredentialPayload,
): Promise<{ success: boolean }> {
  return apiFetch("/credentials", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function deleteCredential(
  id: string,
): Promise<{ success: boolean }> {
  return apiFetch(`/credentials/${id}`, { method: "DELETE" });
}
