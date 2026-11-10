// Global state: the signed-in user (+ CSRF token) and the selected network.
import { createContext, ReactNode, useCallback, useContext, useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, NetworkWithRole, setCsrf, setUnauthorizedHandler, User } from "./api";

interface AuthState {
  user: User | null;
  loading: boolean;
  signedIn: (user: User, csrf: string) => void;
  signOut: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthCtx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const qc = useQueryClient();

  const refresh = useCallback(async () => {
    try {
      const r = await api.me();
      setCsrf(r.csrf_token);
      setUser(r.user);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      qc.clear();
    });
    void refresh();
  }, [refresh, qc]);

  const value: AuthState = {
    user,
    loading,
    refresh,
    signedIn: (u, csrf) => {
      setCsrf(csrf);
      setUser(u);
    },
    signOut: async () => {
      await api.logout().catch(() => {});
      setCsrf("");
      setUser(null);
      qc.clear();
    },
  };
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

export function useAuth() {
  const v = useContext(AuthCtx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}

// --- selected network --------------------------------------------------------

const KEY = "wm.network";
const read = () => {
  try {
    return localStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
};

interface NetState {
  networks: NetworkWithRole[];
  current?: NetworkWithRole;
  select: (id: string) => void;
  loading: boolean;
}
const NetCtx = createContext<NetState | null>(null);

export function NetworkProvider({ children }: { children: ReactNode }) {
  const q = useQuery({ queryKey: ["networks"], queryFn: api.networks });
  const [selected, setSelected] = useState(read);
  const networks = q.data?.networks ?? [];
  const current = networks.find((n) => n.id === selected) ?? networks[0];
  const select = (id: string) => {
    setSelected(id);
    try {
      localStorage.setItem(KEY, id);
    } catch {
      /* private mode: selection just isn't remembered */
    }
  };
  return <NetCtx.Provider value={{ networks, current, select, loading: q.isLoading }}>{children}</NetCtx.Provider>;
}

export function useNetwork() {
  const v = useContext(NetCtx);
  if (!v) throw new Error("useNetwork outside NetworkProvider");
  return v;
}
