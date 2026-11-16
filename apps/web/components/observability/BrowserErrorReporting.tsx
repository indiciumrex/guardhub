"use client";
/**
 * Starts browser error reporting once per page load. Rendered by the root layout only when the
 * server has SENTRY_DSN_WEB (or SENTRY_DSN) set and SENTRY_BROWSER is not "off"; renders nothing.
 */
import { useEffect } from "react";
import { initBrowserErrorTracking } from "@/lib/observability/browser";

export function BrowserErrorReporting({
  environment,
  release,
}: {
  environment: string;
  release?: string;
}) {
  useEffect(() => {
    void initBrowserErrorTracking({ environment, release });
  }, [environment, release]);
  return null;
}
