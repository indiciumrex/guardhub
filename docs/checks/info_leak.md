# Check `info_leak` — information leaks

- **Code:** `apps/scanner/internal/checks/info_leak.go` · tests: `info_leak_test.go`
- **Category:** disclosure · **i18n:** `checks.json` → `info_leak`

## What it detects and how

| Finding key | Severity | Params | Source | Signature |
|---|---|---|---|---|
| `server_version_disclosed` | low | `header`, `value` | `GET /` | `Server` matches `name/1.2…` (e.g. `Apache/2.4.41 (Ubuntu)`, `nginx/1.18.0`); `cloudflare` or `nginx` without a version are not reported |
| `framework_version_disclosed` | low | `header`, `value` | `GET /` | `X-Powered-By` contains a version (`PHP/7.4.3`; plain `Express` or `Next.js` is not reported); `X-AspNet-Version` / `X-AspNetMvc-Version` with digits. One finding per header |
| `stack_trace_exposed` | medium | `path` | 404 probe, then `/` | Python `Traceback (most recent call last):`; Java `at pkg.Class.method(File.java:NN)`; .NET `Server Error in '…' Application` or `at … in …:line NN`; PHP `Fatal error/Parse error/Warning/Notice/Uncaught … on line NN`; Node `at … (/path/file.js:NN:NN)`; Ruby `file.rb:NN:in` |
| `debug_mode_enabled` | high | `framework` | 404 probe, then `/` | Django: `DEBUG = True` + `django`; Laravel: `laravel` + (`ignition` or `window.ignite`); Rails: `Action Controller: Exception caught` or `Rails.root:`; Flask: `Werkzeug Debugger` or `__debugger__` |
| `directory_listing_enabled` | medium | `path` | see below | `<title>Index of /`, `<h1>Index of /`, `Directory listing for /` (Python), `[To Parent Directory]` (IIS); status 200 |

- When a page shows a debug page, the stack-trace finding for that same page is skipped (one root cause, one finding). Only the first page with a trace is reported.
- Only the **first** directory listing is reported, because the fix is server-wide.

## Requests sent (all `GET`)

`/` (cached, shared with preflight and `security_headers`), the fixed 404 probe `/guardhub-scanner-404-probe-7f3a9c1e` (cached, shared), then `/uploads/`, `/images/`, `/assets/`, `/static/`, `/backup/` until a listing is found. That is at most 7 requests, usually 5 new ones.

## Evidence

Headers: kind `http_header`, location `<url>#header=<Name>` (a stable fingerprint per header), payload `Name: value`. Pages: kind `http_response`, payload with status, title and signature name. For stack traces it also includes the matched line, at most 200 characters, with URL credentials masked.

## Plain-language text (en)

For example, `debug_mode_enabled`: "{framework} is running in debug mode". Debug pages show code, settings and sometimes secrets to anyone who triggers an error. Fix: turn off debug in production (Django `DEBUG = False`, Laravel `APP_DEBUG=false`, Rails production environment), redeploy, rotate any secrets that were shown.

## False-positive risk: low

- Every signature is a structural pattern (file:line formats, framework page markup), not a keyword: a blog post that mentions "Python traceback" or "Index of" in prose does not match (tested).
- Version headers are reported only when a version number is present.
- SPA soft-404 pages are handled (tested).

## Why it is do-no-harm

GETs of the home page, one path that does not exist, and a few common folder URLs. We never trigger errors with crafted input; we only look at how the site answers a normal "not found".
