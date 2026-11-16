/**
 * Browser error reporting. The SDK is lazy-loaded (its own chunk, fetched by Next's nonce'd
 * loader, so the strict CSP is unchanged) only when the server rendered <BrowserErrorReporting>,
 * i.e. only when SENTRY_DSN is set. Envelopes go to our same-origin /monitoring tunnel, so
 * connect-src stays 'self'. Errors only: no tracing, replay, feedback, sessions or breadcrumbs.
 */
import { BROWSER_DSN, SERVICE, TUNNEL_PATH } from "./config";
import { scrubEvent } from "./scrub";

type BrowserSdk = typeof import("./browser-sdk");

let sdk: Promise<BrowserSdk | null> | null = null;

export function initBrowserErrorTracking(options: { environment: string; release?: string }) {
  sdk ??= import("./browser-sdk")
    .then((Sentry) => {
      Sentry.init({
        dsn: BROWSER_DSN,
        tunnel: TUNNEL_PATH,
        environment: options.environment,
        release: options.release,
        sendDefaultPii: false,
        sendClientReports: false,
        defaultIntegrations: false,
        integrations: [
          Sentry.globalHandlersIntegration(),
          Sentry.linkedErrorsIntegration(),
          Sentry.dedupeIntegration(),
          Sentry.httpContextIntegration(),
        ],
        maxBreadcrumbs: 0,
        initialScope: { tags: { service: SERVICE, runtime: "browser" } },
        beforeSend: (event) => scrubEvent(event),
        beforeSendTransaction: () => null,
      });
      return Sentry;
    })
    .catch(() => null);
  return sdk;
}

/** Reports an error caught by a React error boundary (no-op when reporting is off). */
export function reportClientError(error: unknown): void {
  void sdk?.then((Sentry) => Sentry?.captureException(error));
}
