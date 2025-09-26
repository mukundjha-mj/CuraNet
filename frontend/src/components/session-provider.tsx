"use client";
import React, { createContext, useContext, useEffect, useState } from "react";
import { apiFetch, setAccessToken, getAccessToken, clearAccessToken } from "@/lib/api";

type Session = {
  user?: { id: string; role: string; name?: string } | null;
  ready: boolean;
};

const SessionContext = createContext<Session>({ ready: false });

export function useSession() {
  return useContext(SessionContext);
}

export default function SessionProvider({ children }: { children: React.ReactNode }) {
  const [state, setState] = useState<Session>({ ready: false, user: null });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        // If we already have a token (from login or storage), try /me directly.
        const token = getAccessToken();
        if (!token) {
          const refresh = await apiFetch<{ accessToken?: string }>("/api/auth/refresh", { method: "POST" });
          if (refresh?.accessToken) setAccessToken(refresh.accessToken);
        }
  const meResp = await apiFetch<unknown>("/api/auth/me", { method: "GET" });
  const me = (meResp as any)?.user ?? meResp; // support { user: {...} } or flat user
  if (!cancelled) setState({ ready: true, user: me as { id: string; role: string; name?: string } });
      } catch {
        clearAccessToken();
        if (!cancelled) setState({ ready: true, user: null });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return <SessionContext.Provider value={state}>{children}</SessionContext.Provider>;
}
