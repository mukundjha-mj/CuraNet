"use client";
import { useEffect, useState } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { apiFetch } from "@/lib/api";

export default function VerifyEmailPage() {
  const params = useSearchParams();
  const router = useRouter();
  const [status, setStatus] = useState<"idle"|"verifying"|"success"|"error">("idle");
  const [message, setMessage] = useState<string>("");

  useEffect(() => {
    const token = params.get("token");
    if (!token) {
      setStatus("error");
      setMessage("Missing verification token.");
      return;
    }
    (async () => {
      try {
        setStatus("verifying");
        await apiFetch("/api/auth/verify-email?token=" + encodeURIComponent(token), { method: "GET" });
        setStatus("success");
        setMessage("Email verified! You can now sign in.");
        setTimeout(() => router.replace("/auth/login"), 1200);
      } catch (e: any) {
        setStatus("error");
        setMessage(e?.message || "Verification failed");
      }
    })();
  }, [params, router]);

  return (
    <div className="max-w-md mx-auto">
      <h1 className="text-2xl font-semibold">Verify your email</h1>
      <p className="mt-3 text-sm text-muted-foreground">
        {status === "idle" && "Preparing…"}
        {status === "verifying" && "Verifying your email…"}
        {status === "success" && message}
        {status === "error" && message}
      </p>
    </div>
  );
}
