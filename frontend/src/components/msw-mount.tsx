"use client";
import { useEffect } from "react";

export default function MswMount() {
  useEffect(() => {
    if (process.env.NODE_ENV === "development") {
      import("@/mocks/browser").then(({ worker }) => {
        worker.start({ onUnhandledRequest: "bypass" });
      });
    }
  }, []);
  return null;
}
