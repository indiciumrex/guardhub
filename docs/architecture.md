# GuardHub — Architecture & Inter-service Contracts

> Companion to `GUARDHUB_STANDARDS.md` (which wins on any conflict). This file pins the exact
> wire contracts between web ↔ API ↔ Redis ↔ scanner so each service can be built and tested
> on its own.

## 1. Request flow

```
browser ──HTTPS──▶ web (Next.js :3000) ──/api/* rewrite──▶ api (FastAPI :8000)
                                                         │        │
                                              XADD gh:jobs│        │ SQL (RLS)
                                                         ▼        ▼
                                  scanner (Go) ◀── Redis 7    PostgreSQL 16
                                      │  XADD gh:events / HSET progress / LPUSH verify reply
                                      ▼
                         api-worker (python -m guardhub_api.worker) ──▶ PostgreSQL
```

- The browser only talks to **web**. Web rewrites `/api/:path*` to `API_INTERNAL_URL` so the
  session cookie is first-party (`SameSite=Strict`, `HttpOnly`, `Secure`).
- **Python decides what to scan** (target, enabled checks from the module registry). **Go
  scans.** The scanner never touches PostgreSQL.

## 2. Queue protocol (Redis) — see ADR-0002

All payloads are UTF-8 JSON in a single stream field named `payload`, with `"v": 1`.

### 2.1 Jobs — stream `gh:jobs`, consumer group `gh-scanners`

The API does `XADD gh:jobs MAXLEN ~ 10000 * payload <json>`. The scanner uses
`XREADGROUP GROUP gh-scanners <consumer> BLOCK 5000 COUNT 1 STREAMS gh:jobs >`, then
`XACK` after it has published the result. Messages pending for more than 10 minutes are
reclaimed with `XAUTOCLAIM`. Whoever starts first creates the group (`XGROUP CREATE … $ MKSTREAM`,
ignoring `BUSYGROUP`).

**Scan job**
```json
{"v":1,"kind":"scan","job_id":"<uuid>","scan_id":"<uuid>",
 "target":"https://example.com","checks":["exposed_env","security_headers"],
 "deadline_seconds":180}
```
- `target` is always an origin: `scheme://host[:port]` with no path. The API normalises it.
- `checks` lists only globally-enabled modules, in catalog order. Unknown ids → skipped and
  reported `failed` with error `unknown_check`.

**Verify job** (ownership proof, ADR-0001)
```json
{"v":1,"kind":"verify","job_id":"<uuid>","target":"https://example.com",
 "token":"ghv_…","reply_key":"gh:verify-reply:<job_id>"}
```
The scanner tries, in order: `GET <target>/.well-known/guardhub-verify.txt` (body trimmed equals
the token, or a line equals it); `GET <target>/` and looks for
`<meta name="guardhub-verification" content="<token>">`; DNS TXT `guardhub-verify=<token>` on
`_guardhub.<host>` then `<host>`. It replies with
`LPUSH <reply_key> <json>` + `EXPIRE <reply_key> 120`:
```json
{"v":1,"job_id":"<uuid>","verified":true,"method":"well_known|meta_tag|dns_txt|null",
 "error":null}
```
`error` is one of `null | "not_found" | "target_unreachable" | "target_blocked" | "timeout"`.

### 2.2 Live progress — hash `gh:scan:{scan_id}:progress`

When a scan starts, the scanner does `HSET` with every requested check set to `queued` and
`EXPIRE 86400`. Each check then moves `queued → running → done | failed`. The API reads this
hash for the visible-scan UI (§8.2).

### 2.3 Events — stream `gh:events`, consumer group `gh-api`

```json
{"v":1,"type":"scan.started","scan_id":"<uuid>","at":"<RFC3339>"}
{"v":1,"type":"scan.completed","scan_id":"<uuid>","at":"<RFC3339>",
 "findings":[<RawFinding per packages/shared/finding.schema.json>],
 "check_results":[{"check_id":"tls_cert","status":"done","error":null}]}
{"v":1,"type":"scan.failed","scan_id":"<uuid>","at":"<RFC3339>",
 "error":"target_unreachable|target_blocked|timeout|internal"}
```
A scan with some failed checks still `completed`; the failure shows in `check_results`.
`check_results[].error` is one of `target_unreachable | target_blocked | timeout | internal |
unknown_check | budget_exceeded`. A malformed job that still carries a usable `scan_id` gets
`scan.failed`/`internal`, and one with a usable `reply_key` gets `verified:false`/`target_unreachable`.
A message reclaimed more than 3 times is acked and dropped, so it can't loop forever. The scanner
never creates the `gh-api` group; the API owns it.
`scan.failed` is only for when the scan can't run at all (e.g. target resolves to a private IP).

## 3. Scanner safety envelope (§9.2 do-no-harm) — enforced in `scanner/internal/probe`

| Rule | Value (env override) |
|---|---|
| Methods | **GET and HEAD only**; anything else is refused by the client |
| User-Agent | `GuardHub-Scanner/1.0 (+https://guardhub.dev/scanner)` |
| Per-request timeout | 10s (`SCANNER_REQUEST_TIMEOUT`) |
| Per-host rate | 4 req/s, burst 2 (`SCANNER_HOST_RPS`) |
| Max requests per scan | 220 (`SCANNER_MAX_REQUESTS_PER_SCAN`; DNS lookups, TLS handshakes and the CT query count too). Sized from the worst case, not the average: the lab's per-check maxima add up to about 100 (Grafana redirects every unknown path to its login, so each probe costs 2), and `subdomain_takeover` caps itself at 70 operations whatever CT returns; `docs/accuracy` lists each check's measured max |
| Retries | max 2, exponential backoff 500ms·2ⁿ, only on network error / 429 / 503 |
| Redirects | max 3; each hop must stay on the same host (http→https allowed) |
| Body read cap | 256 KiB |
| Address guard | dial-time check; loopback/private/link-local/CGNAT/multicast/unspecified/metadata IPs are refused (anti-SSRF, anti-DNS-rebinding). `SCANNER_ALLOW_PRIVATE_HOSTS` (comma list of hostnames) exists **only** for the local e2e demo target |
| Workers | pool of `SCANNER_WORKERS` (default 4) jobs; per scan `SCANNER_CHECK_CONCURRENCY` (default 3) checks |
| Scan deadline | `deadline_seconds` from the job (max 300) |
| Certificates | scan probes skip certificate validation (so a broken cert is *reported* by `tls_cert`, not fatal); ownership-verify probes always validate |
| Per-scan GET cache | identical GETs within one scan are served once (fewer requests to the target); checks still share no state |
| Optional tuning | `SCANNER_HOST_BURST`, `SCANNER_VERIFY_DEADLINE` (20s; must stay below the API's `VERIFY_TIMEOUT_SECONDS`, 25s), `SCANNER_SHUTDOWN_TIMEOUT` (25s), `SCANNER_CONSUMER_NAME` |
| Secret masking | values ≥ 9 chars → `****` + last 4; shorter values → `****` (the last 4 would reveal most of it) |

**One-shot self-scan (dogfooding):** `scanner selfscan <origin> <token>` verifies ownership
with the same verifier, runs every check through the same probe envelope without Redis, and
prints the raw JSON report. Exit codes: 0 means no critical/high findings, 3 means
critical/high findings, and 4 means not verified (nothing scanned). Wrapped by
`ops/scripts/self_scan.py`.

## 4. Public HTTP API (`/api/v1`, JSON)

Errors are always `{"error":{"code":"<snake_code>","message":"<english dev message>"}}`. The web
maps `code` to localised text. A session is a JWT in cookie `gh_session`. Every non-GET request
that carries the cookie must also send header `X-GuardHub-CSRF: 1` (CSRF defence); otherwise
the API returns 403 `csrf_header_missing`.

Locale for localised payloads: `?locale=` → user profile locale → `Accept-Language` → `en`.

### 4.1 Health and catalog
- `GET /health` → `{"status":"ok|degraded|down","components":{"database":"ok","redis":"ok","scanner":"ok|unknown"}}`
- `GET /checks?locale=` → `[{"id":"exposed_env","name":"…","description":"…","enabled":true}]`

### 4.2 Anonymous free scan (ADR-0001)
- `POST /public/challenges` `{"target_url":"example.com"}` → 201
  `{"challenge_id","target_origin","token","expires_at","instructions":{"well_known_url","meta_tag","dns_name","dns_value"}}`
- `POST /public/challenges/{id}/scan` → verifies, then queues → 202
  `{"scan_id","access_token"}`. Errors: 422 `ownership_not_verified` (+ `details.reason`),
  429 `rate_limited`.
- `GET /public/scans/{scan_id}?locale=` with header `X-Scan-Token: <access_token>` → `ScanView`.

### 4.3 Auth
- `POST /auth/register` `{"email","password","locale"}` → 201 `{"user":User,"mfa":"setup_required"}`, sets a pre-MFA cookie
- `POST /auth/login` `{"email","password"}` → 200 `{"mfa":"setup_required"|"required"}`, sets a pre-MFA cookie
- `POST /auth/2fa/setup` (pre-MFA) → `{"secret","otpauth_uri"}`
- `POST /auth/2fa/verify` `{"code"}` → 200 `{"user":User}`, sets a full cookie
- `POST /auth/logout` → 204
- `GET /auth/me` → `User` (any session; `"mfa_complete": bool`)
- `PATCH /auth/me` `{"locale"}` → `User`

`User = {"id","email","role":"user|admin","locale","totp_enabled","mfa_complete","created_at"}`

All routes below need a **full (MFA-complete) session**, because §9.1 makes 2FA mandatory for the dashboard.

### 4.4 Projects and scans
- `GET /projects` → `[Project]`
- `POST /projects` `{"name","target_url"}` → 201 `Project`
- `GET /projects/{id}` · `PATCH /projects/{id}` `{"name"}` · `DELETE /projects/{id}` → 204
- `POST /projects/{id}/verify` → `Project` (or 422 `ownership_not_verified`)
- `POST /projects/claim` `{"scan_id","access_token","name"}` → 201 `Project` (anonymous scan → saved project)
- `GET /projects/{id}/scans` → `[ScanSummary]` (newest first)
- `POST /projects/{id}/scans` → 202 `ScanSummary` (re-scan; needs a verified project; 409 `scan_in_progress`)
- `GET /scans/{scan_id}?locale=` → `ScanView`

```
Project      = {"id","name","target_url","verified":bool,"ownership_verified_at"|null,
                "verification":{"token","well_known_url","meta_tag","dns_name","dns_value"},
                "last_scan": ScanSummary|null,"created_at"}
ScanSummary  = {"id","project_id"|null,"target_url","status":"queued|running|done|failed",
                "score":int|null,"finding_counts":{"critical":0,"high":0,"medium":0,"low":0,"info":0},
                "created_at","started_at"|null,"finished_at"|null,"error"|null}
ScanView     = ScanSummary + {"progress":[{"check_id","name","status":"queued|running|done|failed"}],
                "findings":[FindingView]}
FindingView  = {"id","check_id","finding_key","severity","title","summary","why","fix",
                "evidence":{"kind","location","redacted_payload"},"status":"open|fixed|ignored"}
```

### 4.5 Admin (role `admin` + full MFA session)
- `GET /admin/users?limit&offset` · `GET /admin/scans?limit&offset`
- `GET /admin/modules` → `[{"key","name","category","enabled_global","min_plan"}]`
- `PATCH /admin/modules/{key}` `{"enabled_global":bool}` → module (audited)
- `GET /admin/health` → latest `HealthCheck` per module · `GET /admin/audit?limit`
- `GET /admin/ai` → `{"provider":null,"enabled":false,"active":false}` (no-op seam)

## 5. Score

`score = max(0, 100 − Σ weight(severity))` with weights critical 30, high 15, medium 7, low 2,
info 0. It's deterministic: the same findings always give the same score.

## 6. i18n catalog layout — `packages/shared/i18n/<locale>/`

- `ui.json` — web UI strings (namespaced objects, e.g. `nav.scan`).
- `checks.json` — `{"<check_id>": {"name","description","findings":{"<finding_key>":{"title","summary","why","fix"}}}}`.
  Texts use `{param}` placeholders from `check-ids.json`. Terms in `glossary.json` (CSP, HSTS,
  TLS, CVE…) are never translated.
- Locales: `en` (source, must be complete), `tr` (complete for MVP), and `de fr it es zh-CN hi ru`
  (fallback to `en`; `ops/ci/check_i18n.py` warns about missing keys).

## 7. Error tracking (Sentry protocol) — launch gate H

Each service is off unless its own DSN is set: `SENTRY_DSN_API` (api **and** api-worker),
`SENTRY_DSN_SCANNER`, `SENTRY_DSN_WEB` — one Sentry project each (production: EU region,
`o<org>.ingest.de.sentry.io`). `SENTRY_DSN` is an optional fallback used only when a service's own
DSN is empty. With no DSN no SDK is initialised and nothing changes.

| Service | How it reports | `service` tag |
|---|---|---|
| api | `sentry-sdk` (FastAPI + logging: `log.error`/`log.exception` become events) via **sentry-relay** | `api` |
| api-worker | same SDK via **sentry-relay** | `api-worker` |
| scanner | `sentry-go`: Error-level `slog` records and main-goroutine panics, direct (has egress) | `scanner` |
| web (server) | `@sentry/node`, lazy-loaded in `instrumentation.ts`; Next `onRequestError` (route pattern only), direct | `web` (+ `runtime=node`) |
| web (browser) | `@sentry/browser`, lazy chunk; posts to same-origin `POST /monitoring`, which re-scrubs and forwards | `web` (+ `runtime=browser`) |

- **Env:** the DSNs above, `SENTRY_ENVIRONMENT` (default `production`), release =
  `GUARDHUB_VERSION` (the image tag; compose passes it into every container), `SENTRY_RELAY_URL`
  (api/worker only; default `http://sentry-relay:3000`), `SENTRY_BROWSER=on|off` (web).
- **Network isolation is unchanged.** api/api-worker stay on the `internal: true` backend network.
  The `sentry-relay` service (`getsentry/relay:26.4.0`, proxy mode, config in
  `ops/docker/relay/config.yml`) is the only thing on backend + egress; it forwards Sentry
  envelopes to the host of `SENTRY_DSN_API` (the EU ingest host, via `--upstream-dsn`) and
  nothing else. It runs only with `COMPOSE_PROFILES=sentry`.
  api/worker rewrite the DSN host to the relay, keeping the public key and project id.
- **Errors only:** traces/profiles sample rate 0 in Python/Go; in the JS SDKs `tracesSampleRate`
  is left unset because any number (even 0) switches the tracing machinery on there.
- **Privacy (§9):** `send_default_pii` off and a `before_send` scrubber in every SDK (unit-tested:
  `apps/api/tests/test_observability.py`, `apps/scanner/internal/observability`,
  `apps/web/lib/observability`). Removed: users and client IPs, request bodies, cookies, every
  request header except `User-Agent`, `Accept`, `Accept-Language`, `Content-Type`/`-Length` (so no `Authorization`,
  `X-Scan-Token`, `X-GuardHub-CSRF`, `X-Forwarded-For`), query strings, frame local variables,
  breadcrumbs (web), and in free text: URL credentials, query strings, JWTs, `gh?_` tokens,
  bearer/basic credentials, e-mail and IPv4 addresses, SQL bound parameters.
- **CSP is unchanged** (`connect-src 'self'`, nonce + `strict-dynamic`): the browser SDK is a
  lazy chunk loaded by Next's nonce'd loader and talks only to `/monitoring`. The browser gets a
  placeholder DSN, never the real one. `/monitoring` returns 404 unless reporting is on, accepts
  same-origin posts ≤ 64 KiB only, keeps `event` items only, forces environment/release/service
  server-side, rate-limits (30 burst, 30/min per process) and forwards no client headers or IPs.
- **Proving delivery:** see `ops/runbooks/production.md` §6 (one command per service; each exits
  non-zero if the DSN is missing or the server rejects the event).

## 8. Phase 1 contracts — monitoring, diff, alerts, trusted domains

Schema: `ops/migrations/versions/0003_phase1_monitoring.py`. Trusted domains: ADR-0003.

### 8.1 Background jobs (Arq, ADR-0002)

A new service **`api-jobs`** (`python -m guardhub_api.jobs`, an Arq worker, same image as api) runs
Python-only background work. API ↔ scanner stays on Redis Streams. Arq uses its own key prefix
(`arq:`) in the same Redis. `api-jobs` sits on `backend` **and** `egress`: it is the only Python
process with internet, and only to send alerts (operator-configured SMTP host; Slack webhooks
that pass the strict URL check in §8.4). Registered functions (`guardhub_api/jobs/worker.py`):

| Function | Trigger | What |
|---|---|---|
| `enqueue_due_scans` | cron, every 5 min | §8.2 scheduler |
| `notify_scan(scan_id)` | enqueued by `api-worker` after a project scan completes | §8.4 alerts |
| `recheck_trusted_domains` | cron, daily 04:10 UTC | ADR-0003 background re-proof |

Arq cron jobs are `unique` (one run per tick across workers), so two colours running briefly
during a blue/green switch never double-schedule.

Two small helper jobs are registered too: `notify_paused(project_id)` (queued by the scheduler,
§8.2) and `send_test_notification(user_id, channel)` (queued by the test endpoint, §8.4; the API
itself has no egress). Arq jobs are serialised as **JSON, not pickle** (`jobs/client.py`), job ids
are deterministic where a job must run once (`notify-scan:<scan_id>`), and the registrations are
two lists in `jobs/worker.py` (`FUNCTIONS`, `CRON_JOBS`): one line per job.

### 8.2 Scheduled monitoring

`Project` gains `"scan_frequency": "off|daily|weekly"`, `"next_scan_at": ISO|null`,
`"schedule_paused_reason": null|"ownership_lost"`.

- `PATCH /projects/{id}` accepts `{"scan_frequency": "off|daily|weekly"}` (alongside `name`).
  `daily`/`weekly` need a verified project (422 `ownership_not_verified`). Setting it computes
  `next_scan_at = now + interval + jitter`, jitter = stable per project in [0, 3600) s (spreads
  load). Setting it again clears `schedule_paused_reason`. Audited (`project.schedule_set`).
- `enqueue_due_scans`: picks due projects (`next_scan_at <= now`, not off, not paused) with
  `FOR UPDATE SKIP LOCKED`, at most `SCHEDULER_BATCH` (default 10) per tick, and never more than
  `SCHEDULER_MAX_INFLIGHT` (default 2) scheduled scans queued/running at once (shared host,
  §7.2). For each: if a scan of the project is already in progress, move `next_scan_at` on.
  Ownership is checked exactly like a manual rescan (re-verify when the proof is older than 30
  days; `trusted_domain` projects need their domain `active`). If the proof is gone: set
  `schedule_paused_reason = 'ownership_lost'`, audit `project.schedule_paused`, and send an
  alert (§8.4, kind `monitoring_paused`). Otherwise create a scan with `trigger = 'scheduled'`, enqueue it
  through the existing `scans.queue.enqueue_scan`, and advance `next_scan_at` by one interval.
  The scanner's do-no-harm envelope (§3) applies unchanged.
- "Proof gone" means a definitive answer only: the re-verification found no token (`not_found`),
  the project has no proof at all, or its trusted domain isn't `active`. When the proof can't be
  checked right now (site unreachable/blocked, verify timeout, queue down) nothing is scanned
  and the project is retried within the hour, without pausing. Due projects beyond the in-flight
  cap stay due for the next tick (oldest first). Manual rescans and the scheduler share one code
  path (`projects/scanning.py`); a manual rescan of a `trusted_domain` project whose domain is
  not active gets 422 `trusted_domain_inactive`.

### 8.3 Scan history, diff and trend

`api-worker` stores `scans.failed_checks` (check ids whose `check_results[].status == "failed"`;
a requested check with no result at all counts as failed too, so it can never look "fixed").
`ScanSummary` gains `"trigger": "manual|scheduled|ci"` and `"failed_checks": [check_id]`.

**ScanDiff** (derived, never stored) between a `done` scan *S* and an earlier `done` scan *B* of
the same project (default *B* = the latest `done` scan created before *S*). Only checks that ran
successfully in **both** (`checks - failed_checks` of each) are compared; findings of other
checks are excluded from all three lists. Findings match by `fingerprint`.
- **new:** in *S*, not in *B*, and never in any earlier `done` scan of the project.
- **regressed:** in *S*, not in *B*, but present in some `done` scan before *B* (it came back).
- **fixed:** in *B*, not in *S*.

```
GET /scans/{scan_id}/diff?against=<scan_id>&locale=   (owner; 404 otherwise)
-> {"scan_id","base_scan_id"|null,"project_id","score","base_score"|null,"score_delta"|null,
    "compared_checks":[check_id],"skipped_checks":[check_id],
    "new":[DiffItem],"regressed":[DiffItem],"fixed":[DiffItem],"unchanged_count":int}
DiffItem = {"fingerprint","check_id","finding_key","severity","title","summary"}
```
`base_scan_id = null` when *S* is the first done scan (baseline: all lists empty,
`unchanged_count` = number of findings). `against` must be an earlier done scan of the same
project (422 `invalid_comparison` otherwise). Lists are sorted by severity, then title.
With an explicit older `against`, a finding seen only in scans between *B* and *S* counts as
**new** (it was not there at *B* nor before it). A diff of a scan that isn't `done` yet is 422
`scan_not_done`. Owner checks are explicit on top of RLS (the admin role can read other users'
rows under RLS, so every `/projects/*`, `/scans/*/diff` and `/account/notifications*` route also
checks `user_id`).

`GET /projects/{id}/trend?limit=30` (1-90) -> `[{"scan_id","finished_at","score","trigger"}]`,
done scans, oldest first.

### 8.4 Alerts (e-mail + optional Slack)

Only **changes** alert. After a project scan completes, `notify_scan` computes the ScanDiff
against the previous done scan. No previous scan: baseline, no alert. Per enabled channel:
- `new` or `regressed` non-empty (and the matching `notify_*` flag on): **alert** listing them
  (title + severity + one-line summary, never evidence), plus fixed ones as a summary line.
- only `fixed` non-empty and `notify_fixed` on: short **fixed summary**.
- nothing changed: nothing is sent.
Each send is a `notifications` row (unique per scan x channel): retries (max 3, backoff) never
duplicate. Text comes from `packages/shared/i18n/<locale>/notifications.json` in the user's
locale (`en`, `tr` complete), carries the GuardHub brand + "Powered by HKSolutions" (§8.1) and
links to `{PUBLIC_BASE_URL}/account/projects/{project_id}/compare/{scan_id}`.

- **E-mail:** SMTP (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`,
  `SMTP_SECURITY=starttls|tls`; plaintext only for a local sink: `SMTP_SECURITY=none` AND
  `SMTP_HOST` listed in `SMTP_INSECURE_HOSTS`). Empty `SMTP_HOST`: status `skipped`
  (`email_not_configured`).
- **Slack:** incoming webhook only. Accepted URL:
  `^https://hooks\.slack\.com/services/[A-Za-z0-9_/-]{10,200}$`. Stored encrypted (AAD = user
  id); never returned by the API. POST with 5 s timeout, no redirects, no other hosts.
- **paused** alerts (§8.2) and **test** messages have no scan: they are `notification_events`
  rows (migration 0004; kind `monitoring_paused | test`), unique per (job id, channel), with the
  same send-once locking and bounded retries. A separate table keeps the migration expand-only:
  the previous release requires a scan id on every `notifications` row and never reads this one.
- The history merges both tables. It shows real alerts (scan changes + monitoring paused) by
  default; test messages only when asked (`show=test|all`), marked "Test" in the UI.
- Delivery errors are stored as short codes only (`smtp_error`, `slack_http_404`, …). 4xx from
  Slack (bad/revoked webhook) isn't retried; timeouts, 429 and 5xx are, up to 3 attempts.

```
GET  /account/notifications -> {"email_enabled","notify_new","notify_regression","notify_fixed",
                                "slack_configured":bool,"email":"<user email>"}
PUT  /account/notifications   {"email_enabled","notify_new","notify_regression","notify_fixed",
                               "slack_webhook_url"?: string|null}  (omitted = keep, null = remove)
     -> the GET view. 422 invalid_slack_webhook. Audited (account.notifications_updated; never the URL).
POST /account/notifications/test {"channel":"email|slack"} -> 202 {"status":"queued"};
     429 after 3 attempts/hour; 422 slack_not_configured | email_not_configured.
GET  /account/notifications/history?limit=20&show=alerts|test|all  (default alerts)
     -> [{"id","kind":"scan_change|monitoring_paused|test","scan_id"|null,"project_id"|null,
          "channel","status","new_count","regression_count","fixed_count","created_at","sent_at"}]
     (counts are 0 for kinds other than scan_change). 422 for any other `show`.
```

### 8.5 Admin trusted domains (ADR-0003)

All routes: role `admin` re-checked from the DB + full MFA session; anyone else gets 404.
```
GET    /admin/trusted-domains -> [TrustedDomain]
POST   /admin/trusted-domains {"target_url"} -> 201 TrustedDomain (status "pending")
POST   /admin/trusted-domains/{id}/verify -> TrustedDomain ("active") | 422 ownership_not_verified
DELETE /admin/trusted-domains/{id} -> 204 (status "revoked")
POST   /admin/trusted-domains/{id}/scan -> 202 ScanSummary (creates or reuses the admin's project
        for that origin, ownership_method "trusted_domain"; 422 trusted_domain_inactive if not active)
TrustedDomain = {"id","host","target_origin","status":"pending|active|suspended|revoked",
                 "verification":{"token","well_known_url","meta_tag","dns_name","dns_value"},
                 "method"|null,"verified_at"|null,"last_checked_at"|null,"suspended_at"|null,"created_at"}
```
`POST /projects` by an admin whose active trusted domains include the target's exact host
(`host[:port]` of the normalised origin, same scheme) creates the project already verified with
`ownership_method = 'trusted_domain'`. Any other target (any user, admins included) follows the
normal proof flow. Rescans of `trusted_domain` projects require the domain to be `active`.
Audit actions: `admin.trusted_domain.{added,verified,suspended,reactivated,revoked,scan}`.

Clarifications (as built):
- 404 `not_found` also for signed-out visitors and admins without a full MFA session (no 401/403).
- A domain counts only while `status = 'active'` AND its last successful proof (`verified_at`,
  refreshed by every passing check) is under 30 days old. `scan` re-proves a stale active domain
  inline first; `POST /projects` simply treats it as untrusted.
- `verify`: a failure keeps a `pending` domain pending and suspends an `active` one (422
  `ownership_not_verified`); success on a `suspended` domain is audited as `reactivated`.
- Errors: 404 `trusted_domain_not_found` (someone else's, revoked or missing: indistinguishable),
  409 `trusted_domain_exists` (one live entry per host, whatever the scheme), 422
  `trusted_domain_limit_reached` (50 live per admin), 409 `scan_in_progress`, 429 `rate_limited`
  (verify 10 per 10 min, scan 10 per hour, per domain).
- `scan` on an existing project for the origin re-marks it `trusted_domain` (fresh proof time).
- Rescans and (§8.2) scheduled scans of `trusted_domain` projects call
  `admin.trusted_domains.ownership.require_trusted_domain(user_id, origin)` (DB role re-checked);
  a revoked, suspended or stale domain gives 422 `trusted_domain_inactive` and nothing is queued.
