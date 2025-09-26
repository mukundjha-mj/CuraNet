"use client";
import { useEffect } from "react";
import { initMonitoring } from "@/lib/monitoring";

export default function MonitoringMount() {
  useEffect(() => {
    initMonitoring();
  }, []);
  return null;
}
