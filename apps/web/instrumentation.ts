/**
 * Next.js instrumentation hook. Error tracking is OFF (and the SDK is never loaded) unless
 * SENTRY_DSN_WEB (or SENTRY_DSN) is set at runtime. Node runtime only; the edge middleware is not instrumented.
 * The imports sit inside `NEXT_RUNTIME === "nodejs"` blocks so the edge bundle never sees them.
 */
import type { Instrumentation } from "next";

export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    if (!process.env.SENTRY_DSN_WEB && !process.env.SENTRY_DSN) return;
    const { initServerErrorTracking } = await import("./lib/observability/server");
    initServerErrorTracking();
  }
}

export const onRequestError: Instrumentation.onRequestError = async (error, request, context) => {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    if (!process.env.SENTRY_DSN_WEB && !process.env.SENTRY_DSN) return;
    const { captureRequestError } = await import("./lib/observability/server");
    captureRequestError(error, request, context);
  }
};
