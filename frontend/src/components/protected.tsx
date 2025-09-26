"use client";
import { useEffect } from "react";
import { useSession } from "@/components/session-provider";

export default function Protected({ children }: { children: React.ReactNode }) {
  const { ready, user } = useSession();
  useEffect(() => {
    if (ready && !user) {
      window.location.href = "/auth/login";
    }
  }, [ready, user]);
  if (!ready) return <div className="animate-pulse text-sm text-muted-foreground">Loading…</div>;
  if (!user) return null;
  return children;
}
