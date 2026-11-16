/**
 * Small, pure navigation helpers shared by server and client code.
 */

export const DEFAULT_AFTER_LOGIN = "/account";

/** Only same-site relative paths are allowed as post-login targets (no open redirects). */
export function safeNextPath(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\")) {
    return DEFAULT_AFTER_LOGIN;
  }
  return next;
}

export function loginUrl(next: string): string {
  return `/account/login?next=${encodeURIComponent(safeNextPath(next))}`;
}

export type TwoFactorMode = "setup" | "verify";

export function twoFactorUrl(next: string, mode?: TwoFactorMode): string {
  const base = `/account/2fa?next=${encodeURIComponent(safeNextPath(next))}`;
  return mode ? `${base}&mode=${mode}` : base;
}

/** sessionStorage keys for the anonymous scan flow. The scan token never goes in a URL. */
export const scanTokenKey = (scanId: string) => `guardhub:scan-token:${scanId}`;
export const PENDING_CLAIM_KEY = "guardhub:pending-claim";

export interface PendingClaim {
  scanId: string;
  name: string;
}

/** Display name for a target URL: its host, or the raw value if it doesn't parse. */
export function hostOf(targetUrl: string): string {
  try {
    return new URL(targetUrl).host;
  } catch {
    return targetUrl;
  }
}
