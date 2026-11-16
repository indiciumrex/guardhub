import { describe, expect, it, vi } from "vitest";
import { buildCsp } from "@/lib/csp";
import { BROWSER_DSN, errorTrackingConfig, parseDsn } from "./config";
import { FILTERED, scrubEvent, scrubText } from "./scrub";
import { handleTunnel, MAX_ENVELOPE_BYTES, rewriteBrowserEnvelope, TokenBucket } from "./tunnel";

// Fake DSN public id (32 hex chars, like a real one).
const PUBLIC_ID = "f".repeat(32);
const DSN = `https://${PUBLIC_ID}@o42.ingest.example.io/4501234`;
const EVENT_ID = "a".repeat(32);

function sensitiveEvent(): Record<string, unknown> {
  return {
    event_id: EVENT_ID,
    message: "boom for alice@example.com from 203.0.113.9",
    user: { id: "u1", email: "alice@example.com", ip_address: "{{auto}}" },
    request: {
      method: "GET",
      url: "https://guardhub.example/scan/1?locale=en&token=abc#frag",
      query_string: "locale=en&token=abc",
      data: { password: "hunter2-hunter2" },
      cookies: { gh_session: "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl" },
      headers: {
        "User-Agent": "Mozilla/5.0",
        Referer: "https://guardhub.example/account?next=/admin",
        Authorization: "Bearer abcdefghijklmnop",
        Cookie: "gh_session=secret",
        "X-Scan-Token": "scan-token-value",
        "X-GuardHub-CSRF": "1",
      },
    },
    exception: {
      values: [
        {
          type: "Error",
          value: "fetch https://api.example/x?token=ghv_abcdefghijkl failed",
          stacktrace: { frames: [{ function: "f", vars: { password: "hunter2" } }] },
        },
      ],
    },
    extra: { access_token: "t0k3n", ok: "fine" },
    tags: { service: "web" },
    breadcrumbs: [{ category: "fetch", data: { url: "https://example.com/?secret=1" } }],
  };
}

describe("scrubEvent", () => {
  it("removes every sensitive field", () => {
    const out = scrubEvent(sensitiveEvent());
    const dumped = JSON.stringify(out);
    for (const leaked of [
      "alice@example.com",
      "203.0.113.9",
      "{{auto}}",
      "hunter2",
      "ghv_abcdefghijkl",
      "abcdefghijklmnop",
      "scan-token-value",
      "gh_session",
      "token=abc",
      "secret=1",
      "t0k3n",
      "eyJhbGciOi",
      "next=/admin",
      "#frag",
    ]) {
      expect(dumped).not.toContain(leaked);
    }
    expect(out.user).toBeUndefined();
    expect(out.breadcrumbs).toBeUndefined();
    expect(out.request).toEqual({
      method: "GET",
      url: "https://guardhub.example/scan/1",
      headers: { "User-Agent": "Mozilla/5.0" },
    });
    expect(out.extra).toEqual({ access_token: FILTERED, ok: "fine" });
  });

  it("keeps harmless text", () => {
    expect(scrubText("render failed in /scan/[scanId] (v10.78.0)")).toBe(
      "render failed in /scan/[scanId] (v10.78.0)",
    );
  });
});

describe("config", () => {
  it("is off without a DSN and parses the envelope endpoint", () => {
    expect(errorTrackingConfig({})).toBeNull();
    expect(errorTrackingConfig({ SENTRY_DSN: "not a dsn" })).toBeNull();
    const cfg = errorTrackingConfig({ SENTRY_DSN: DSN, GUARDHUB_VERSION: "1.2.3" });
    expect(cfg).toMatchObject({ environment: "production", release: "1.2.3", browser: true });
    expect(cfg?.dsn.envelopeUrl).toBe("https://o42.ingest.example.io/api/4501234/envelope/");
    expect(parseDsn(`https://${PUBLIC_ID}@sentry.example/prefix/7`)?.envelopeUrl).toBe(
      "https://sentry.example/prefix/api/7/envelope/",
    );
    expect(errorTrackingConfig({ SENTRY_DSN: DSN, SENTRY_BROWSER: "off" })?.browser).toBe(false);
  });

  it("does not change the CSP: connect-src stays 'self'", () => {
    expect(buildCsp("n", false)).toContain("connect-src 'self';");
  });
});

function envelope(dsn: string, items: Array<[object, object]>): string {
  return [
    JSON.stringify({ event_id: EVENT_ID, dsn, sent_at: "2026-01-01T00:00:00Z" }),
    ...items.flatMap(([h, p]) => [JSON.stringify(h), JSON.stringify(p)]),
  ].join("\n");
}

const config = errorTrackingConfig({
  SENTRY_DSN: DSN,
  SENTRY_ENVIRONMENT: "prod-eu",
  GUARDHUB_VERSION: "1.2.3",
})!;

describe("rewriteBrowserEnvelope", () => {
  it("keeps scrubbed events, drops other items and forces server-side tags", () => {
    const raw = envelope(BROWSER_DSN, [
      [{ type: "client_report" }, { discarded_events: [] }],
      [
        { type: "event" },
        { ...sensitiveEvent(), environment: "evil", release: "evil", tags: { service: "x" } },
      ],
    ]);
    const result = rewriteBrowserEnvelope(raw, config);
    expect(result.kind).toBe("forward");
    if (result.kind !== "forward") return;
    expect(result.events).toBe(1);
    const lines = result.body.split("\n");
    expect(lines).toHaveLength(3);
    expect(JSON.parse(lines[0]!)).not.toHaveProperty("dsn");
    const event = JSON.parse(lines[2]!);
    expect(event.environment).toBe("prod-eu");
    expect(event.release).toBe("1.2.3");
    expect(event.tags).toEqual({ service: "web", runtime: "browser" });
    expect(result.body).not.toContain("alice@example.com");
  });

  it("rejects foreign or malformed envelopes", () => {
    expect(
      rewriteBrowserEnvelope(envelope(DSN, [[{ type: "event" }, { event_id: EVENT_ID }]]), config)
        .kind,
    ).toBe("invalid");
    expect(rewriteBrowserEnvelope("not json", config).kind).toBe("invalid");
    expect(
      rewriteBrowserEnvelope(
        envelope(BROWSER_DSN, [[{ type: "event" }, { event_id: "x" }]]),
        config,
      ).kind,
    ).toBe("invalid");
    expect(
      rewriteBrowserEnvelope(envelope(BROWSER_DSN, [[{ type: "session" }, {}]]), config).kind,
    ).toBe("empty");
  });
});

describe("handleTunnel", () => {
  const goodBody = envelope(BROWSER_DSN, [
    [{ type: "event" }, { event_id: EVENT_ID, message: "x" }],
  ]);
  const post = (body: string, headers: Record<string, string> = {}) =>
    new Request("https://guardhub.example/monitoring", { method: "POST", body, headers });

  it("is 404 when reporting is off or browser reporting is disabled", async () => {
    const fetchMock = vi.fn();
    const limiter = new TokenBucket(5, 5);
    expect(
      (await handleTunnel(post(goodBody), { config: null, limiter, fetch: fetchMock })).status,
    ).toBe(404);
    expect(
      (
        await handleTunnel(post(goodBody), {
          config: { ...config, browser: false },
          limiter,
          fetch: fetchMock,
        })
      ).status,
    ).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards a valid envelope to the server DSN only, without client headers", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    const res = await handleTunnel(
      post(goodBody, { "sec-fetch-site": "same-origin", cookie: "gh_session=x" }),
      {
        config,
        limiter: new TokenBucket(5, 5),
        fetch: fetchMock,
      },
    );
    expect(res.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("https://o42.ingest.example.io/api/4501234/envelope/");
    const headers = init.headers as Record<string, string>;
    expect(Object.keys(headers).sort()).toEqual(["Content-Type", "X-Sentry-Auth"]);
    expect(headers["X-Sentry-Auth"]).toContain(`sentry_key=${PUBLIC_ID}`);
  });

  it("refuses cross-site, oversized, invalid and rate-limited posts", async () => {
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    const deps = { config, limiter: new TokenBucket(1, 0), fetch: fetchMock };
    expect(
      (await handleTunnel(post(goodBody, { "sec-fetch-site": "cross-site" }), deps)).status,
    ).toBe(403);
    expect((await handleTunnel(post("x".repeat(MAX_ENVELOPE_BYTES + 1)), deps)).status).toBe(413);
    expect((await handleTunnel(post("garbage"), deps)).status).toBe(400);
    expect((await handleTunnel(post(goodBody), deps)).status).toBe(200);
    expect((await handleTunnel(post(goodBody), deps)).status).toBe(429);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("reports upstream failure as 502", async () => {
    const deps = {
      config,
      limiter: new TokenBucket(5, 5),
      fetch: vi.fn(async () => {
        throw new Error("offline");
      }),
    };
    expect((await handleTunnel(post(goodBody), deps)).status).toBe(502);
  });
});
