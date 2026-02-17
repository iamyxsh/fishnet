import { API_BASE } from "@/lib/constants";
import type { ApiError } from "./types";

const MOCK_EXPLICIT = import.meta.env.VITE_MOCK === "true";
const IS_DEV = import.meta.env.DEV;

let mockModule: typeof import("./mock") | null = null;
let useMock: boolean = MOCK_EXPLICIT;

// In dev, probe the backend once at startup.
// If unreachable, flip to mock for the entire session.
if (IS_DEV && !MOCK_EXPLICIT) {
  fetch(`${API_BASE}/status`, { method: "HEAD" })
    .then((res) => {
      const ct = res.headers.get("content-type") ?? "";
      // Vite SPA fallback returns 200 text/html — not a real backend
      if (!ct.includes("application/json")) {
        useMock = true;
      }
    })
    .catch(() => {
      useMock = true;
    });

  // Don't block rendering — default to mock until probe completes
  useMock = true;
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
  if (useMock) {
    const mock = await getMock();
    return mock.handleMock<T>(path, opts);
  }

  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...opts?.headers },
    ...opts,
  });

  if (!res.ok) {
    const body = (await res.json().catch(() => ({
      error: res.statusText,
      code: res.status,
    }))) as ApiError;
    throw new FetchError(res.status, body);
  }

  return res.json() as Promise<T>;
}
