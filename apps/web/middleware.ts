/**
 * Per-request middleware:
 * 1. Locale: if there is no valid NEXT_LOCALE cookie, negotiate one from Accept-Language and
 *    set it (HttpOnly, SameSite=Lax, 1 year). The request cookie is also updated so this very
 *    render already uses it.
 * 2. CSP: generates a nonce and sets the Content-Security-Policy header. Next.js reads the
 *    nonce from the request's CSP header and applies it to its own scripts.
 * 3. Exposes the pathname to Server Components (post-login redirect targets).
 */
import { NextResponse, type NextRequest } from "next/server";
import { buildCsp, generateNonce } from "@/lib/csp";
import { isLocale, LOCALE_COOKIE, localeCookieOptions } from "@/lib/i18n/config";
import { negotiateLocale } from "@/lib/i18n/negotiate";

export function middleware(request: NextRequest) {
  const nonce = generateNonce();
  const csp = buildCsp(nonce, process.env.NODE_ENV === "development");

  const existing = request.cookies.get(LOCALE_COOKIE)?.value;
  const needsLocale = !isLocale(existing);
  const locale = needsLocale ? negotiateLocale(request.headers.get("accept-language")) : existing;
  if (needsLocale) request.cookies.set(LOCALE_COOKIE, locale);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);
  requestHeaders.set("x-guardhub-pathname", request.nextUrl.pathname + request.nextUrl.search);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  if (needsLocale) response.cookies.set(LOCALE_COOKIE, locale, localeCookieOptions);
  return response;
}

export const config = {
  matcher: [
    {
      source: "/((?!api/|_next/static|_next/image|favicon.ico|icon.svg|robots.txt).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
