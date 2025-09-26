"use client";
import * as Sentry from "@sentry/nextjs";
import posthog from "posthog-js";

declare global {
  interface Window { __CURANET_MON_INIT__?: boolean }
}

export function initMonitoring() {
  if (typeof window === "undefined") return;
  if (!window.__CURANET_MON_INIT__) {
    window.__CURANET_MON_INIT__ = true;
    if (process.env.NEXT_PUBLIC_SENTRY_DSN) {
      Sentry.init({ dsn: process.env.NEXT_PUBLIC_SENTRY_DSN, tracesSampleRate: 0.1 });
    }
    if (process.env.NEXT_PUBLIC_POSTHOG_KEY) {
      posthog.init(process.env.NEXT_PUBLIC_POSTHOG_KEY, {
        api_host: process.env.NEXT_PUBLIC_POSTHOG_HOST || "https://app.posthog.com",
        autocapture: false,
        capture_pageview: false,
      });
    }
  }
}
