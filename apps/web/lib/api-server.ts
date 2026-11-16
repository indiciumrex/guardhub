/**
 * Server-side API client: calls API_INTERNAL_URL directly and forwards the visitor's cookie
 * and language so the API sees the same session. Only import from Server Components,
 * route handlers and server actions.
 */
import "server-only";
import { headers } from "next/headers";
import { buildApiPath, requestJson, type ApiFetchOptions } from "./api";

export function apiInternalUrl(): string {
  return (process.env.API_INTERNAL_URL ?? "http://api:8000").replace(/\/+$/, "");
}

export async function serverApiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const incoming = await headers();
  const forwarded: Record<string, string> = {};
  const cookie = incoming.get("cookie");
  if (cookie) forwarded.Cookie = cookie;
  const acceptLanguage = incoming.get("accept-language");
  if (acceptLanguage) forwarded["Accept-Language"] = acceptLanguage;
  const userAgent = incoming.get("user-agent");
  if (userAgent) forwarded["User-Agent"] = userAgent;

  return requestJson<T>(
    `${apiInternalUrl()}${buildApiPath(path, options.query)}`,
    options,
    forwarded,
    {
      cache: "no-store",
    },
  );
}
