"use client";
import { useEffect } from "react";
import { useSession } from "@/components/session-provider";
import { useRouter, useSearchParams } from "next/navigation";

export default function DashboardRedirect() {
  const { user, ready } = useSession();
  const router = useRouter();
  const params = useSearchParams();
  useEffect(() => {
    if (!ready) return;
    if (!user) return; // Protected pages will route unauthenticated users to /auth/login
  const role = user?.role ?? "patient";
    const from = params.get("from");
    // Avoid looping back to login if we came from there; send to role home.
    if (from === "login") router.replace(`/${role}`);
    else router.replace(`/${role}`);
  }, [ready, user, router, params]);
  return <p className="text-sm text-muted-foreground">Redirecting…</p>;
}
