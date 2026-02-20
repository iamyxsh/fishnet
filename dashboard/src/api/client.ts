import { API_BASE } from "@/lib/constants";
import type { ApiError } from "./types";

export const TOKEN_KEY = "fishnet_token";

export class FetchError extends Error {
  constructor(
    public status: number,
    public body: ApiError,
  ) {
    super(body.error);
    this.name = "FetchError";
  }
}

export async function apiFetch<T>(
  path: string,
  opts?: RequestInit,
): Promise<T> {
  const isAuthEndpoint = path.startsWith("/auth/");

  // Build headers: auto-inject auth token unless caller provides Authorization
  const incomingHeaders = (opts?.headers ?? {}) as Record<string, string>;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  const token = localStorage.getItem(TOKEN_KEY);
  if (token && !incomingHeaders["Authorization"]) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { ...headers, ...incomingHeaders },
  });

  if (!res.ok) {
    const body = (await res.json().catch(() => ({
      error: res.statusText,
      code: res.status,
    }))) as ApiError;

    // Auto-clear token on 401 for non-auth endpoints (stale session)
    if (res.status === 401 && !isAuthEndpoint) {
      localStorage.removeItem(TOKEN_KEY);
      window.location.href = "/login";
    }

    throw new FetchError(res.status, body);
  }

  return res.json() as Promise<T>;
}
