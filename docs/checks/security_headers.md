# Check `security_headers` — security headers and cookie flags

- **Code:** `apps/scanner/internal/checks/headers.go` · tests: `headers_test.go`
- **Category:** hardening · **i18n:** `checks.json` → `security_headers`

## What it detects

| Finding key | Severity | Params | Trigger |
|---|---|---|---|
| `csp_missing` | medium | – | no `Content-Security-Policy` header (`-Report-Only` does not count) |
| `hsts_missing` | medium | – | https only: no `Strict-Transport-Security` |
| `hsts_weak` | low | `max_age` | https only: HSTS `max-age` < 15552000 (180 days); missing or unparsable max-age is reported as `0` |
| `nosniff_missing` | low | – | `X-Content-Type-Options` is not `nosniff` |
| `clickjacking_unprotected` | low | – | no `X-Frame-Options` **and** no CSP `frame-ancestors` |
| `cookie_flags_missing` | medium | `cookie_name`, `missing_flags` | one finding per cookie lacking `Secure` (https only), `HttpOnly` or `SameSite`; `missing_flags` is a comma list such as `Secure, HttpOnly` |

## Requests sent

One `GET /` of the origin, following same-host redirects (max 3, http→https allowed). The response is shared through the per-scan cache with the preflight and `info_leak`, so this check usually sends **no extra request**.

## How it verifies

It reads the response headers of the final response. HSTS is evaluated only when the final URL is https, because browsers ignore HSTS over http. If the root redirects to **another host** (for example `example.com` → `www.example.com`), the scanner does not follow it. In that case only HSTS and cookies are evaluated on the redirect response, because CSP, nosniff and frame options apply to documents, not redirects.

## Evidence

Kind `http_header`. The location is the final URL; for cookies it is `<url>#set-cookie=<name>` so each cookie has a stable fingerprint. The payload lists the relevant response headers. Cookie **values are masked** (`session=****1234; Path=/`).

## Plain-language text (en)

For example, `csp_missing`: "No Content-Security-Policy (CSP)". Without it, browsers run any script that ends up on your pages, so one injected script can steal sessions. The fix steps start in report-only mode, then list the domains you use, switch to enforcing, and show where to set the header (Next.js `headers()` in `next.config.js`, Express `helmet()`, `vercel.json`, Netlify `_headers`, nginx `add_header … always`, Cloudflare Transform Rules). The other keys follow the same structure; see the catalog.

## False-positive risk: low to medium

- Header presence is unambiguous. API-only origins (JSON at `/`) may not need CSP or frame protection. This is low severity, and the user can mark the finding as ignored.
- `HttpOnly` is reported for every cookie that lacks it. Some cookies must be readable by JavaScript (CSRF double-submit tokens, consent banners); the fix text explains when that is acceptable.

## Why it is do-no-harm

A single cached GET of the home page. It sends no cookies and never sets or replays any.
