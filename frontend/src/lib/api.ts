"use client";
import { QueryClient } from "@tanstack/react-query";
import Cookies from "js-cookie";

// In-memory access token store (kept client-only)
let accessToken: string | null = null;
let refreshingPromise: Promise<string | null> | null = null;

export const setAccessToken = (token: string | null) => {
  accessToken = token;
  try {
    if (typeof window !== "undefined") {
      if (token) localStorage.setItem("access_token", token);
      else localStorage.removeItem("access_token");
    }
  } catch {}
};

export const getAccessToken = () => accessToken;

// initialize from storage on module load (client only)
try {
  if (typeof window !== "undefined") {
    const saved = localStorage.getItem("access_token");
    if (saved) accessToken = saved;
  }
} catch {}

export function clearAccessToken() {
  setAccessToken(null);
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: true,
      retry: 2,
    },
    mutations: {
      retry: 1,
    },
  },
});

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

type RequestOptions = {
  method?: HttpMethod;
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  // for CSRF double-submit token
  csrf?: string;
};

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3000";

async function refreshTokenSingleFlight(): Promise<string | null> {
  if (!refreshingPromise) { 
    refreshingPromise = fetch(`${BASE_URL}/api/auth/refresh`, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then(async (res) => {
        if (!res.ok) return null;
        const data = await res.json();
        // expect { accessToken: string }
        const token = data?.accessToken ?? null;
        setAccessToken(token);
        return token;
      })
      .finally(() => {
        // reset after settle to allow subsequent refresh
        setTimeout(() => (refreshingPromise = null), 0);
      });
  }
  return refreshingPromise;
}

export async function apiFetch<T = unknown>(
  path: string,
  { method = "GET", body, headers = {}, signal, csrf }: RequestOptions = {}
): Promise<T> {
  const url = path.startsWith("http") ? path : `${BASE_URL}${path}`;
  const finalHeaders: Record<string, string> = {
    "Content-Type": "application/json",
    ...headers,
  };

  const token = getAccessToken();
  if (token) finalHeaders["Authorization"] = `Bearer ${token}`;

  // double-submit CSRF pattern: read csrf cookie and echo header
  const csrfCookie = Cookies.get("csrf-token");
  const csrfToken = csrf ?? csrfCookie;
  if (csrfToken) finalHeaders["X-CSRF-Token"] = csrfToken;

  const res = await fetch(url, {
    method,
    credentials: "include", // send refresh cookie to same origin API
    headers: finalHeaders,
    signal,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (res.status === 401) {
    // try refresh
    const newToken = await refreshTokenSingleFlight();
    if (!newToken) {
      setAccessToken(null);
      throw new Error("UNAUTHORIZED");
    }
    // retry once
  const retryHeaders: Record<string, string> = { ...finalHeaders, Authorization: `Bearer ${newToken}` };
    const retryRes = await fetch(url, {
      method,
      credentials: "include",
      headers: retryHeaders,
      signal,
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!retryRes.ok) {
      const text = await retryRes.text();
      throw new Error(text || `Request failed with ${retryRes.status}`);
    }
    const out: T = (await retryRes.json()) as unknown as T;
    return out;
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || `Request failed with ${res.status}`);
  }

  if (res.status === 204) return undefined as unknown as T;
  const out: T = (await res.json()) as unknown as T;
  return out;
}

export const keys = {
  me: ["me"] as const,
};
