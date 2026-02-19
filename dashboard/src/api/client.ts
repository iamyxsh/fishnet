import { API_BASE } from "@/lib/constants";
import type { ApiError } from "./types";

export const TOKEN_KEY = "fishnet_token";

const MOCK_EXPLICIT = import.meta.env.VITE_MOCK === "true";
const IS_DEV = import.meta.env.DEV;

let mockModule: typeof import("./mock") | null = null;

/** Whether to use mock for non-auth (dashboard data) endpoints */
let useMockForData: boolean = MOCK_EXPLICIT;

/** Whether the real backend is available for auth endpoints */
let backendAvailable: boolean = false;

// In dev, probe the backend once at startup.
if (IS_DEV && !MOCK_EXPLICIT) {
  fetch(`${API_BASE}/auth/status`)
    .then((res) => {
      const ct = res.headers.get("content-type") ?? "";
      if (ct.includes("application/json")) {
        backendAvailable = true;
        // Backend is up for auth, but dashboard data endpoints
        // may not exist yet — keep mock for non-auth routes
        useMockForData = true;
      }
    })
    .catch(() => {
      useMockForData = true;
    });

  // Don't block rendering — default to mock until probe completes
  useMockForData = true;
}

async function getMock() {
  if (!mockModule) {
    mockModule = await import("./mock");
  }
  return mockModule;
}

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
  const isAlertEndpoint = path.startsWith("/alerts");

  // Auth & alert endpoints → real backend if available, otherwise mock
  // Data endpoints → always mock until backend implements them
  const isBackendEndpoint = isAuthEndpoint || isAlertEndpoint;
  const shouldMock = isBackendEndpoint
    ? !backendAvailable
    : useMockForData;

  if (shouldMock || MOCK_EXPLICIT) {
    const mock = await getMock();
    return mock.handleMock<T>(path, opts);
  }

  // Build headers: auto-inject auth token unless caller provides Authorization
  const incomingHeaders = (opts?.headers ?? {}) as Record<string, string>;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Auto-inject stored token for authenticated requests
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
