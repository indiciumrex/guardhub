/**
 * Privacy filter for error events (GUARDHUB_STANDARDS §9). Used by the server SDK's beforeSend,
 * the browser SDK's beforeSend AND again by the /monitoring tunnel (never trust the browser).
 * Removes: users and IP addresses, request bodies, cookies, query strings, all request headers
 * except a small allowlist, frame variables, breadcrumbs, and credentials/tokens/e-mail/IPv4
 * addresses inside free text. Pure functions, no SDK imports, unit-tested.
 */

export const FILTERED = "[Filtered]";

type Json = Record<string, unknown>;

const SENSITIVE_KEYS = new Set(
  [
    "authorization",
    "proxy-authorization",
    "cookie",
    "cookies",
    "set-cookie",
    "x-scan-token",
    "x-guardhub-csrf",
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "remote_addr",
    "ip_address",
    "client_ip",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "totp",
    "code",
    "otp",
    "jwt",
    "session",
    "gh_session",
    "dsn",
    "query_string",
    "body",
  ].map((k) => k.replace(/-/g, "_")),
);

const SAFE_HEADERS = new Set(["user-agent", "accept-language"]);

const URL_USERINFO = /\b([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^/\s@]*@/g;
const URL_QUERY = /\b([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s?#"'<>]*)\?[^\s#"'<>]*/g;
const JWT = /\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}/g;
const GH_TOKEN = /\bgh[a-z]_[A-Za-z0-9_-]{8,}/g;
const BEARER = /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}/gi;
const EMAIL = /\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b/g;
const IPV4 = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

function isRecord(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isSensitive(key: string): boolean {
  return SENSITIVE_KEYS.has(key.toLowerCase().replace(/-/g, "_"));
}

export function scrubText(value: string): string {
  return value
    .replace(URL_USERINFO, `$1${FILTERED}@`)
    .replace(URL_QUERY, `$1?${FILTERED}`)
    .replace(JWT, FILTERED)
    .replace(GH_TOKEN, FILTERED)
    .replace(BEARER, `$1 ${FILTERED}`)
    .replace(EMAIL, FILTERED)
    .replace(IPV4, FILTERED);
}

/** Recursively scrubs JSON-like data: sensitive keys → [Filtered], strings → scrubText. */
export function scrubValue(value: unknown, depth = 0): unknown {
  if (depth > 8) return FILTERED;
  if (typeof value === "string") return scrubText(value);
  if (Array.isArray(value)) return value.map((v) => scrubValue(v, depth + 1));
  if (isRecord(value)) {
    const out: Json = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = isSensitive(k) ? FILTERED : scrubValue(v, depth + 1);
    }
    return out;
  }
  return value;
}

/** Keeps scheme, host and path only (no credentials, query or fragment). */
export function stripUrl(raw: string): string {
  try {
    const url = new URL(raw);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    // Relative or malformed: cut at the first ? or #.
    return scrubText(raw.split(/[?#]/, 1)[0] ?? "");
  }
}

function scrubRequest(request: Json): Json {
  const out: Json = {};
  if (typeof request.method === "string") out.method = request.method;
  if (typeof request.url === "string") out.url = stripUrl(request.url);
  if (isRecord(request.headers)) {
    const headers: Json = {};
    for (const [k, v] of Object.entries(request.headers)) {
      if (SAFE_HEADERS.has(k.toLowerCase()) && typeof v === "string") headers[k] = scrubText(v);
    }
    out.headers = headers;
  }
  // data (body), cookies, query_string and env are never kept.
  return out;
}

function scrubFrames(container: unknown): void {
  if (!isRecord(container) || !isRecord(container.stacktrace)) return;
  const frames = container.stacktrace.frames;
  if (!Array.isArray(frames)) return;
  for (const frame of frames) {
    if (isRecord(frame)) {
      delete frame.vars;
      for (const key of ["abs_path", "filename"] as const) {
        const v = frame[key];
        if (typeof v === "string" && /[?#]/.test(v)) frame[key] = stripUrl(v);
      }
    }
  }
}

/** The event filter. Mutates and returns the same object. */
export function scrubEvent<T extends object>(event: T): T {
  const e = event as Json;
  delete e.user;
  delete e.breadcrumbs; // console/fetch/DOM trails can carry URLs and user input
  if (isRecord(e.request)) e.request = scrubRequest(e.request);
  for (const section of ["exception", "threads"] as const) {
    const block = e[section];
    if (isRecord(block) && Array.isArray(block.values)) {
      for (const item of block.values) {
        scrubFrames(item);
        if (isRecord(item) && typeof item.value === "string") item.value = scrubText(item.value);
      }
    }
  }
  for (const key of ["message", "logentry", "extra", "contexts", "tags"] as const) {
    if (key in e) e[key] = scrubValue(e[key]);
  }
  if (typeof e.transaction === "string") e.transaction = stripUrl(e.transaction);
  return event;
}
