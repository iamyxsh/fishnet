import { apiFetch } from "../client";
import type {
  AuthStatusResponse,
  LoginResponse,
  SetupResponse,
  LogoutResponse,
} from "../types";

export function fetchAuthStatus(token?: string) {
  const headers: Record<string, string> = {};
  if (token) headers["Authorization"] = `Bearer ${token}`;
  return apiFetch<AuthStatusResponse>("/auth/status", { headers });
}

export function postSetup(password: string, confirm: string) {
  return apiFetch<SetupResponse>("/auth/setup", {
    method: "POST",
    body: JSON.stringify({ password, confirm }),
  });
}

export function postLogin(password: string) {
  return apiFetch<LoginResponse>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ password }),
  });
}

export function postLogout(token: string) {
  return apiFetch<LogoutResponse>("/auth/logout", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
}
