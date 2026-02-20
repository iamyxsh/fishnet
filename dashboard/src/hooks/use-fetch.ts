import { useState, useEffect, useCallback, useRef } from "react";

interface UseFetchOptions {
  deps?: unknown[];
  /** Poll interval in ms. Omit or 0 to disable polling. */
  pollInterval?: number;
}

interface UseFetchResult<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
  refetch: () => void;
}

export function useFetch<T>(
  fetcher: () => Promise<T>,
  optsOrDeps: UseFetchOptions | unknown[] = {},
): UseFetchResult<T> {
  // Backwards-compatible: accept plain deps array or options object
  const opts: UseFetchOptions = Array.isArray(optsOrDeps)
    ? { deps: optsOrDeps }
    : optsOrDeps;
  const deps = opts.deps ?? [];
  const pollInterval = opts.pollInterval ?? 0;

  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const mountedRef = useRef(true);

  const fetcherRef = useRef(fetcher);
  fetcherRef.current = fetcher;

  const refetch = useCallback(() => {
    setLoading(true);
    setError(null);
    fetcherRef
      .current()
      .then((result) => {
        if (mountedRef.current) {
          setData(result);
          setLoading(false);
        }
      })
      .catch((err: unknown) => {
        if (mountedRef.current) {
          setError(err instanceof Error ? err : new Error(String(err)));
          setLoading(false);
        }
      });
  }, []);

  // Silent refetch for polling — doesn't flash loading state
  const silentRefetch = useCallback(() => {
    fetcherRef
      .current()
      .then((result) => {
        if (mountedRef.current) setData(result);
      })
      .catch(() => {
        // Swallow polling errors silently
      });
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    refetch();
    return () => {
      mountedRef.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  // Polling
  useEffect(() => {
    if (!pollInterval || pollInterval <= 0) return;
    const id = setInterval(silentRefetch, pollInterval);
    return () => clearInterval(id);
  }, [pollInterval, silentRefetch]);

  return { data, loading, error, refetch };
}
