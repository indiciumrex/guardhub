/**
 * Error-tracking configuration from the RUNTIME environment (no build-time DSN, so one image
 * works with or without Sentry). Everything is off unless SENTRY_DSN_WEB (or SENTRY_DSN) is set.
 * - SENTRY_DSN_WEB (fallback SENTRY_DSN), SENTRY_ENVIRONMENT (default "production"), GUARDHUB_VERSION (release).
 * - SENTRY_BROWSER=off disables browser reporting and the /monitoring tunnel (default on).
 */

export const SERVICE = "web";

/** Where the browser SDK posts envelopes: our own origin, so CSP connect-src stays 'self'. */
export const TUNNEL_PATH = "/monitoring";

/**
 * The browser never learns the real DSN: it gets this placeholder, and the tunnel re-addresses
 * every envelope to the server's own DSN. The tunnel rejects envelopes that don't carry it.
 */
export const BROWSER_DSN = "https://guardhub@tunnel.invalid/1";

export type ParsedDsn = {
  dsn: string;
  publicKey: string;
  projectId: string;
  envelopeUrl: string;
};

export type ErrorTrackingConfig = {
  dsn: ParsedDsn;
  environment: string;
  release: string | undefined;
  browser: boolean;
};

export function parseDsn(raw: string): ParsedDsn | null {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    return null;
  }
  const segments = url.pathname.split("/").filter(Boolean);
  const projectId = segments.pop();
  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    !url.username ||
    !projectId ||
    !/^\d+$/.test(projectId)
  ) {
    return null;
  }
  const prefix = segments.length ? `/${segments.join("/")}` : "";
  return {
    dsn: raw.trim(),
    publicKey: decodeURIComponent(url.username),
    projectId,
    envelopeUrl: `${url.protocol}//${url.host}${prefix}/api/${projectId}/envelope/`,
  };
}

export function errorTrackingConfig(
  env: Record<string, string | undefined> = process.env,
): ErrorTrackingConfig | null {
  // Per-service DSN wins; SENTRY_DSN is only a fallback.
  const raw = env.SENTRY_DSN_WEB?.trim() || env.SENTRY_DSN?.trim();
  if (!raw) return null;
  const dsn = parseDsn(raw);
  if (!dsn) return null;
  const browserFlag = (env.SENTRY_BROWSER ?? "on").trim().toLowerCase();
  return {
    dsn,
    environment: env.SENTRY_ENVIRONMENT?.trim() || "production",
    release: env.GUARDHUB_VERSION?.trim() || undefined,
    browser: !["off", "false", "0", "no"].includes(browserFlag),
  };
}
