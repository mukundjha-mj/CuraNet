"use client";
import { useEffect, useState } from "react";

export default function OfflineBanner() {
  const [online, setOnline] = useState(true);
  useEffect(() => {
    const set = () => setOnline(navigator.onLine);
    set();
    window.addEventListener("online", set);
    window.addEventListener("offline", set);
    return () => {
      window.removeEventListener("online", set);
      window.removeEventListener("offline", set);
    };
  }, []);

  if (online) return null;
  return (
    <div className="w-full bg-yellow-100 text-yellow-900 text-center text-sm py-1">
      Offline mode — changes will sync when you're back online.
    </div>
  );
}
