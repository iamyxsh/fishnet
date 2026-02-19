import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useRef,
} from "react";
import {
  fetchAuthStatus,
  postLogin,
  postSetup,
  postLogout,
} from "@/api/endpoints/auth";
import { TOKEN_KEY } from "@/api/client";

interface AuthState {
  token: string | null;
  initialized: boolean;
  authenticated: boolean;
  /** True during initial auth status check */
  loading: boolean;
}

interface AuthContextValue extends AuthState {
  login: (password: string) => Promise<void>;
  setup: (password: string, confirm: string) => Promise<void>;
  logout: () => Promise<void>;
}

export const AuthContext = createContext<AuthContextValue>({
  token: null,
  initialized: false,
  authenticated: false,
  loading: true,
  login: async () => {},
  setup: async () => {},
  logout: async () => {},
});

export function useAuth() {
  return useContext(AuthContext);
}

export function useAuthProvider(): AuthContextValue {
  const [state, setState] = useState<AuthState>(() => ({
    token: localStorage.getItem(TOKEN_KEY),
    initialized: false,
    authenticated: false,
    loading: true,
  }));
  const mountedRef = useRef(true);

  // Check auth status on mount
  useEffect(() => {
    mountedRef.current = true;
    const token = localStorage.getItem(TOKEN_KEY);

    fetchAuthStatus(token ?? undefined)
      .then((res) => {
        if (!mountedRef.current) return;
        setState({
          token: res.authenticated ? token : null,
          initialized: res.initialized,
          authenticated: res.authenticated,
          loading: false,
        });
        if (!res.authenticated) localStorage.removeItem(TOKEN_KEY);
      })
      .catch(() => {
        if (!mountedRef.current) return;
        setState({
          token: null,
          initialized: false,
          authenticated: false,
          loading: false,
        });
      });

    return () => {
      mountedRef.current = false;
    };
  }, []);

  const login = useCallback(async (password: string) => {
    const res = await postLogin(password);
    localStorage.setItem(TOKEN_KEY, res.token);
    setState((prev) => ({
      ...prev,
      token: res.token,
      authenticated: true,
      initialized: true,
    }));
  }, []);

  const setup = useCallback(async (password: string, confirm: string) => {
    await postSetup(password, confirm);
    // Auto-login after setup so user lands on dashboard immediately
    const loginRes = await postLogin(password);
    localStorage.setItem(TOKEN_KEY, loginRes.token);
    setState((prev) => ({
      ...prev,
      token: loginRes.token,
      authenticated: true,
      initialized: true,
    }));
  }, []);

  const logout = useCallback(async () => {
    const token = localStorage.getItem(TOKEN_KEY);
    if (token) {
      try {
        await postLogout(token);
      } catch {
        /* best effort — clear local state regardless */
      }
    }
    localStorage.removeItem(TOKEN_KEY);
    setState({
      token: null,
      initialized: true, // still initialized, just logged out
      authenticated: false,
      loading: false,
    });
  }, []);

  return { ...state, login, setup, logout };
}
