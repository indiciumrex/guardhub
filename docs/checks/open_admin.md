# Check `open_admin` — open admin and debug panels

- **Code:** `apps/scanner/internal/checks/open_admin.go` (+ `signatures.go`) · tests: `open_admin_test.go`
- **Category:** exposure · **i18n:** `checks.json` → `open_admin`

## What it detects and how

Every probe is a `GET` of a fixed path. A hit needs **status 200 (unless stated) and a product-specific content signature** (case-insensitive). The response must also not be byte-identical to the soft-404 baseline (`/guardhub-scanner-404-probe-7f3a9c1e`, shared and cached).

| Path | Finding key (severity) | `product` | Signature |
|---|---|---|---|
| `/console` | `debug_console_exposed` (critical) | Werkzeug debugger | `werkzeug` + (`__debugger__` or `interactive console`) |
| `/actuator` | `debug_endpoint_exposed` (high) | Spring Boot Actuator | `"_links"` + `/actuator` |
| `/actuator/env` | `debug_endpoint_exposed` (high) | Spring Boot Actuator | `"propertySources"` + `"activeProfiles"` |
| `/_profiler/` | `debug_endpoint_exposed` (high) | Symfony Profiler | (`symfony profiler` or `sf-toolbar`) + `profiler` |
| `/telescope` | `debug_endpoint_exposed` (high) | Laravel Telescope | `window.Telescope` |
| `/_debugbar/open` | `debug_endpoint_exposed` (high) | Laravel Debugbar | JSON with `"utime"` + `"datetime"` + `"uri"` |
| `/rails/info/properties` | `debug_endpoint_exposed` (high) | Rails info page | `Rails version` + `Ruby version` |
| `/phpmyadmin/`, `/phpMyAdmin/`, `/pma/` | `db_admin_exposed` (high) | phpMyAdmin | `phpmyadmin` + (`pma_username`, `pma_password`, `pmahomme`, `phpmyadmin.css` or `<title>phpmyadmin`) |
| `/adminer.php`, `/adminer/` | `db_admin_exposed` (high) | Adminer | `adminer` + (`auth[driver]` or `adminer.org`) |
| `/server-status` | `server_status_exposed` (medium) | – | `Apache Server Status for` |
| `/nginx_status` | `server_status_exposed` (medium) | – | `Active connections:` + `server accepts handled requests` |
| `/wp-login.php` | `admin_login_exposed` (low) | – | password `<input>` + (`id="loginform"`, `wp-submit` or `user_login`) |
| `/admin`, `/admin/login`, `/administrator/` | `admin_login_exposed` (low) | – | password `<input>` and the final URL path or `<title>` mentions "admin" |

**Grouping:** probes of the same product (or group) stop after the first hit, and the remaining paths of that group are **not requested**. For example, once `/phpmyadmin/` matches, `/phpMyAdmin/` and `/pma/` are skipped, and only one admin-login finding is reported. `/actuator` and `/actuator/env` are separate findings because `/env` exposes configuration.

Django debug pages (`DEBUG = True`) are detected by `info_leak` (`debug_mode_enabled`) on its 404 probe, so they are not reported twice here.

Requests: at most 19 (18 paths + the shared baseline), or fewer when groups match.

## Evidence

Kind `http_response`; location is the probed URL. The payload has the status, content type, page `<title>` and **the name of the matched signature only**. Page bodies are never copied, because pages such as `/actuator/env` may contain secrets.

## Plain-language text (en)

For example, `debug_console_exposed`: "{product} debug console is publicly reachable". This kind of console lets a visitor run code on your server, which means a full takeover. Fix: turn off debug mode in production (Flask `debug=False`, `FLASK_DEBUG=0`), redeploy, and check your logs. `admin_login_exposed` is deliberately calm ("common and not a problem on its own"); it suggests 2FA, rate limiting or an IP allowlist.

## False-positive risk: low (medium for `admin_login_exposed`)

- Signatures are product markup, not words that appear in normal prose (tested: a "telescopes for sale" page, a status page saying "operational", and a prose mention of phpMyAdmin are all rejected).
- A 403/401 with the signature text does not count as exposure.
- SPA catch-alls are rejected by the baseline comparison; a catch-all that contains a login form everywhere is rejected too (tested).
- `admin_login_exposed` can match a customer-facing login titled "Admin"; it is low severity for that reason.

## Why it is do-no-harm

Read-only GETs of fixed paths, rate-limited. **No form is ever submitted, no login is attempted and no console command is sent.** Debug consoles are identified from their landing page only.
