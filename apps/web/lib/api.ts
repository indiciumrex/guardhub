/**
 * Typed fetch client for the GuardHub API (docs/architecture.md §4).
 * - Browser calls go to same-origin `/api/v1/...` (rewritten to the API by next.config).
 * - Every non-GET request carries `X-GuardHub-CSRF: 1`.
 * - Error envelopes `{"error":{"code","message"}}` become a typed `ApiError`.
 * The server-side variant (cookie forwarding) lives in lib/api-server.ts.
 */
import type { ApiErrorBody } from "./types";

export const API_PREFIX = "/api/v1";
export const CSRF_HEADER = "X-GuardHub-CSRF";
export const SCAN_TOKEN_HEADER = "X-Scan-Token";

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: Record<string, unknown> | undefined;

  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export type HttpMethod = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";

export interface ApiFetchOptions {
  method?: HttpMethod;
  /** JSON-serialised as the request body. */
  body?: unknown;
  /** Added as query parameters; undefined values are skipped. */
  query?: Record<string, string | number | undefined>;
  headers?: Record<string, string>;
  signal?: AbortSignal;
}

function isApiErrorBody(value: unknown): value is ApiErrorBody {
  if (typeof value !== "object" || value === null || !("error" in value)) return false;
  const error = (value as { error: unknown }).error;
  return (
    typeof error === "object" &&
    error !== null &&
    typeof (error as { code?: unknown }).code === "string"
  );
}

/** Turns a non-2xx response into an ApiError, tolerating non-JSON bodies. */
export async function parseErrorResponse(response: Response): Promise<ApiError> {
  let payload: unknown = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  if (isApiErrorBody(payload)) {
    const { code, message, details } = payload.error;
    return new ApiError(response.status, code, message, details);
  }
  return new ApiError(response.status, "http_error", `HTTP ${response.status}`);
}

export function buildApiPath(path: string, query?: ApiFetchOptions["query"]): string {
  const normalised = path.startsWith("/") ? path : `/${path}`;
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined) params.set(key, String(value));
  }
  const qs = params.toString();
  return `${API_PREFIX}${normalised}${qs ? `?${qs}` : ""}`;
}

/** Shared request core used by the browser and server clients. */
export async function requestJson<T>(
  url: string,
  options: ApiFetchOptions,
  extraHeaders: Record<string, string> = {},
  init: RequestInit = {},
): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = {
    Accept: "application/json",
    ...extraHeaders,
    ...options.headers,
  };
  if (method !== "GET") headers[CSRF_HEADER] = "1";
  if (options.body !== undefined) headers["Content-Type"] = "application/json";

  let response: Response;
  try {
    response = await fetch(url, {
      ...init,
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      signal: options.signal,
    });
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === "AbortError") throw cause;
    throw new ApiError(0, "network_error", "The API could not be reached.");
  }

  if (!response.ok) throw await parseErrorResponse(response);
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

/** Browser-side API call (same-origin; the session cookie is sent automatically). */
export function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  return requestJson<T>(
    buildApiPath(path, options.query),
    options,
    {},
    {
      credentials: "same-origin",
      cache: "no-store",
    },
  );
}
