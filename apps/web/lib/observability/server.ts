/**
 * Server-side error reporting for the Next.js node runtime. Loaded lazily from
 * instrumentation.ts ONLY when SENTRY_DSN_WEB (or SENTRY_DSN) is set, so the SDK is never even imported otherwise.
 * Errors only: no tracing (tracesSampleRate left unset — in the JS SDK any number, even 0,
 * switches the tracing machinery on), no OpenTelemetry setup, no default integrations (so no
 * http/console breadcrumbs and no local variables), and every event goes through scrubEvent.
 */
import * as Sentry from "@sentry/node";
import type { ErrorEvent } from "@sentry/node";
import { errorTrackingConfig, SERVICE, type ErrorTrackingConfig } from "./config";
import { scrubEvent } from "./scrub";

let active = false;

export function serverOptions(config: ErrorTrackingConfig): Sentry.NodeOptions {
  return {
    dsn: config.dsn.dsn,
    environment: config.environment,
    release: config.release,
    sendDefaultPii: false,
    includeLocalVariables: false,
    skipOpenTelemetrySetup: true,
    registerEsmLoaderHooks: false,
    defaultIntegrations: false,
    integrations: [
      Sentry.onUncaughtExceptionIntegration(),
      Sentry.onUnhandledRejectionIntegration(),
      Sentry.linkedErrorsIntegration(),
      Sentry.dedupeIntegration(),
      Sentry.functionToStringIntegration(),
      Sentry.nodeContextIntegration(),
    ],
    maxBreadcrumbs: 0,
    initialScope: { tags: { service: SERVICE, runtime: "node" } },
    beforeSend: (event: ErrorEvent) => scrubEvent(event),
    beforeSendTransaction: () => null,
  };
}

export function initServerErrorTracking(): boolean {
  const config = errorTrackingConfig();
  if (!config || active) return active;
  Sentry.init(serverOptions(config));
  active = true;
  return true;
}

type RequestInfo = { method: string; path: string };
type ErrorContext = { routerKind: string; routePath: string; routeType: string };

/** Called from instrumentation.ts onRequestError (RSC render, route handlers, actions). */
export function captureRequestError(
  error: unknown,
  request: RequestInfo,
  context: ErrorContext,
): void {
  if (!active) return;
  Sentry.captureException(error, {
    // The route PATTERN (e.g. /scan/[scanId]), never the concrete URL or its query string.
    tags: { route: context.routePath, route_type: context.routeType, router: context.routerKind },
    contexts: { request: { method: request.method } },
  });
}
