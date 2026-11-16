import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiFetch, buildApiPath } from "./api";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function lastCall(mock: ReturnType<typeof vi.fn>): { url: string; init: RequestInit } {
  const call = mock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  return { url: call[0] as string, init: call[1] as RequestInit };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiFetch", () => {
  it("does not send the CSRF header on GET and adds query params", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(200, { ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await apiFetch("/public/scans/abc", {
      query: { locale: "tr" },
      headers: { "X-Scan-Token": "t" },
    });

    const { url, init } = lastCall(fetchMock);
    expect(url).toBe("/api/v1/public/scans/abc?locale=tr");
    const headers = init.headers as Record<string, string>;
    expect(headers["X-GuardHub-CSRF"]).toBeUndefined();
    expect(headers["X-Scan-Token"]).toBe("t");
  });

  it("adds X-GuardHub-CSRF: 1 and a JSON body on non-GET requests", async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse(201, { id: "p1" }));
    vi.stubGlobal("fetch", fetchMock);

    const result = await apiFetch<{ id: string }>("/projects", {
      method: "POST",
      body: { name: "Site", target_url: "example.com" },
    });

    expect(result).toEqual({ id: "p1" });
    const { init } = lastCall(fetchMock);
    const headers = init.headers as Record<string, string>;
    expect(init.method).toBe("POST");
    expect(headers["X-GuardHub-CSRF"]).toBe("1");
    expect(headers["Content-Type"]).toBe("application/json");
    expect(init.body).toBe(JSON.stringify({ name: "Site", target_url: "example.com" }));
  });

  it("sends the CSRF header even without a body (e.g. POST /auth/logout)", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", fetchMock);

    await expect(apiFetch("/auth/logout", { method: "POST" })).resolves.toBeUndefined();
    const headers = lastCall(fetchMock).init.headers as Record<string, string>;
    expect(headers["X-GuardHub-CSRF"]).toBe("1");
  });

  it("parses the error envelope into a typed ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(422, {
          error: {
            code: "ownership_not_verified",
            message: "proof not found",
            details: { reason: "not_found" },
          },
        }),
      ),
    );

    const error = await apiFetch("/public/challenges/c1/scan", { method: "POST" }).catch(
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(ApiError);
    const apiError = error as ApiError;
    expect(apiError.status).toBe(422);
    expect(apiError.code).toBe("ownership_not_verified");
    expect(apiError.details).toEqual({ reason: "not_found" });
  });

  it("falls back to http_error for a non-JSON error body", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("Bad gateway", { status: 502 })));
    await expect(apiFetch("/health")).rejects.toMatchObject({ status: 502, code: "http_error" });
  });

  it("maps network failures to network_error", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    await expect(apiFetch("/health")).rejects.toMatchObject({ status: 0, code: "network_error" });
  });
});

describe("buildApiPath", () => {
  it("skips undefined query values", () => {
    expect(buildApiPath("checks", { locale: undefined, limit: 5 })).toBe("/api/v1/checks?limit=5");
  });
});
