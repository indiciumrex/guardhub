/**
 * Same-origin tunnel for browser error events (POST /monitoring). The browser SDK posts here so
 * the CSP keeps connect-src 'self'; this handler re-addresses envelopes to the server's DSN.
 * Hardening: 404 unless browser reporting is on; same-origin fetches only; 64 KiB body cap;
 * global token bucket (bounds quota abuse); only `event` items survive, each re-scrubbed and
 * re-tagged on the server (environment/release/service come from our env, not the browser);
 * no client headers or IPs are forwarded. Does not proxy anything else.
 */
import { BROWSER_DSN, errorTrackingConfig, type ErrorTrackingConfig } from "./config";
import { scrubEvent, scrubValue } from "./scrub";

export const MAX_ENVELOPE_BYTES = 64 * 1024;
const MAX_EVENTS = 5;
const EVENT_ID = /^[0-9a-f]{32}$/;

type Json = Record<string, unknown>;

function isRecord(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseJson(line: string | undefined): unknown {
  if (line === undefined) return undefined;
  try {
    return JSON.parse(line);
  } catch {
    return undefined;
  }
}

export type RewriteResult =
  { kind: "forward"; body: string; events: number } | { kind: "empty" } | { kind: "invalid" };

/** Parses a browser envelope, keeps scrubbed `event` items only, and re-serialises it. */
export function rewriteBrowserEnvelope(raw: string, config: ErrorTrackingConfig): RewriteResult {
  const lines = raw.replace(/\n+$/, "").split("\n");
  const header = parseJson(lines[0]);
  if (!isRecord(header) || header.dsn !== BROWSER_DSN) return { kind: "invalid" };
  if (lines.length % 2 !== 1) return { kind: "invalid" }; // header + (item header, payload) pairs
  const events: Json[] = [];
  for (let i = 1; i < lines.length; i += 2) {
    const itemHeader = parseJson(lines[i]);
    if (!isRecord(itemHeader) || typeof itemHeader.type !== "string") return { kind: "invalid" };
    if (itemHeader.type !== "event") continue; // client reports, sessions, replays… are dropped
    const payload = parseJson(lines[i + 1]);
    if (
      !isRecord(payload) ||
      typeof payload.event_id !== "string" ||
      !EVENT_ID.test(payload.event_id)
    ) {
      return { kind: "invalid" };
    }
    events.push(payload);
  }
  if (events.length > MAX_EVENTS) return { kind: "invalid" };
  if (events.length === 0) return { kind: "empty" };

  const items = events.map((event) => {
    scrubEvent(event);
    const tags = isRecord(event.tags) ? (scrubValue(event.tags) as Json) : {};
    event.tags = { ...tags, service: "web", runtime: "browser" };
    event.environment = config.environment;
    if (config.release) event.release = config.release;
    else delete event.release;
    delete event.sdkProcessingMetadata;
    return `${JSON.stringify({ type: "event" })}\n${JSON.stringify(event)}`;
  });
  const first = events[0];
  const envelopeHeader = { event_id: first?.event_id, sent_at: new Date().toISOString() };
  return {
    kind: "forward",
    body: [JSON.stringify(envelopeHeader), ...items].join("\n"),
    events: items.length,
  };
}

/** Process-wide token bucket: `capacity` envelopes, refilled at `perMinute`. */
export class TokenBucket {
  private tokens: number;
  private last: number;

  constructor(
    private readonly capacity: number,
    private readonly perMinute: number,
    private readonly now: () => number = Date.now,
  ) {
    this.tokens = capacity;
    this.last = now();
  }

  take(): boolean {
    const t = this.now();
    this.tokens = Math.min(
      this.capacity,
      this.tokens + ((t - this.last) / 60_000) * this.perMinute,
    );
    this.last = t;
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }
}

async function readCapped(request: Request, limit: number): Promise<string | null> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > limit) return null;
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(Buffer.concat(chunks));
}

export type TunnelDeps = {
  config: ErrorTrackingConfig | null;
  limiter: TokenBucket;
  fetch: typeof fetch;
};

const empty = (status: number) =>
  new Response(null, { status, headers: { "Cache-Control": "no-store" } });

export async function handleTunnel(request: Request, deps: TunnelDeps): Promise<Response> {
  const config = deps.config;
  if (!config?.browser) return empty(404);
  // Browsers mark cross-site requests; only our own pages may post here.
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin") return empty(403);
  const raw = await readCapped(request, MAX_ENVELOPE_BYTES);
  if (raw === null) return empty(413);
  const result = rewriteBrowserEnvelope(raw, config);
  if (result.kind === "invalid") return empty(400);
  if (result.kind === "empty") return empty(200);
  if (!deps.limiter.take()) return empty(429);
  try {
    const upstream = await deps.fetch(config.dsn.envelopeUrl, {
      method: "POST",
      body: result.body,
      headers: {
        "Content-Type": "application/x-sentry-envelope",
        "X-Sentry-Auth": `Sentry sentry_version=7, sentry_key=${config.dsn.publicKey}, sentry_client=guardhub-web-tunnel/1.0`,
      },
      signal: AbortSignal.timeout(5_000),
      cache: "no-store",
    });
    return empty(upstream.ok ? 200 : 502);
  } catch {
    return empty(502);
  }
}

// 30 envelopes burst, 30/min sustained per web process.
const defaultLimiter = new TokenBucket(30, 30);

export function tunnelPost(request: Request): Promise<Response> {
  return handleTunnel(request, { config: errorTrackingConfig(), limiter: defaultLimiter, fetch });
}
