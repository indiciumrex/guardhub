# Runbook — running GuardHub in production (guardhub.dev)

## 1. Where it runs (shared host)

guardhub.dev runs on a **shared** Ubuntu host next to other projects. Rules: touch nothing outside
`/opt/guardhub`, the compose project `guardhub`, `/etc/nginx/sites-enabled/guardhub.dev.conf`,
`/etc/cron.d/guardhub-backup` and the `guardhub.dev` certbot renewal file.

| Path | What |
|---|---|
| `/opt/guardhub/releases/<sha>` | one directory per release (git archive of that commit) |
| `/opt/guardhub/current`, `previous` | symlinks used by deploy/rollback |
| `/opt/guardhub/shared/.env` | production secrets, `root:root 600`, generated on the server; **keep an offline copy of `DATA_ENCRYPTION_KEY`** (backups are useless without it) |
| `/opt/guardhub/backups` | `pg_dump -Fc` + manifest, 14-day retention (`700`) |
| `/opt/guardhub/acme`, `selfverify` | certbot webroot; our own ownership-proof file for the self-scan |

- **Proxy:** the host's existing nginx owns 80/443. `ops/deploy/nginx/guardhub.dev.conf` is the
  only GuardHub vhost: TLS 1.2/1.3, `server_tokens off`, `X-Forwarded-For` **overwritten** with
  the peer address (so `TRUSTED_PROXY_HOPS=2`: nginx + the web `/api` rewrite). No `http2` on the
  listen line: on nginx 1.24 that flips HTTP/2 for every site on :443. Always `nginx -t` before
  `systemctl reload nginx`. The certificate renews via the host certbot timer; the `renew_hook`
  in `/etc/letsencrypt/renewal/guardhub.dev.conf` reloads nginx.
- **Network exposure:** only `web` is published, on `127.0.0.1:18700`. Postgres, Redis, the API
  and the relay are never published (Docker-published ports bypass UFW, so never bind `0.0.0.0`).
  `guardhub_backend` is `internal: true`. UFW allows 22/80/443 only.
- **Neighbours:** `docker-compose.prod.yml` caps CPU/memory/pids per container and the scanner at
  2 scans x 2 checks. Images are built off-host, so builds never compete for the host CPU.

## 2. Deploy, rollback, status (zero-downtime blue/green)

**Layout.** The data layer (postgres, redis, sentry-relay) is the long-lived compose project
`guardhub`. The app layer runs as `guardhub-blue` or `guardhub-green` on `127.0.0.1:18701` /
`:18702` (`ops/deploy/compose.color.yml` joins them to the data networks). nginx proxies to the
upstream in `/opt/guardhub/shared/nginx-upstream.conf`, which `guardhub-ctl.sh` rewrites; the
active colour and versions are in `/opt/guardhub/state/`.

From a clean checkout on a workstation with Docker and SSH access:

```bash
ops/deploy/deploy.sh root@<host>     # build images here, ship release + images, activate
```

`activate <sha>`:
1. pre-deploy backup;
2. runs the release's migrations while the current colour keeps serving, so **migrations must be
   expand-only** (add tables/columns/constraints that old code ignores; to drop or rename, ship
   the code that stops using it first, then the destructive migration in a later release);
3. starts the release in the idle colour and waits for its `/api/v1/health` = ok;
4. switches the nginx upstream (`nginx -t`, then a graceful reload: in-flight requests finish on
   the old colour) and checks public health through nginx;
5. stops the old colour (containers kept for a fast rollback).
If the new colour never becomes healthy, nothing is switched and it is torn down.

```bash
ssh root@<host> /opt/guardhub/current/ops/deploy/guardhub-ctl.sh status
ssh root@<host> /opt/guardhub/current/ops/deploy/guardhub-ctl.sh rollback        # previous colour
ssh root@<host> /opt/guardhub/current/ops/deploy/guardhub-ctl.sh exec api <cmd>  # active colour
```

Rollback starts the previous colour, health-gates it, switches nginx back and stops the current
one, also with no downtime. The schema is left as is (expand-only makes that safe). Rehearse any
change to this flow with `ops/deploy/tests/bluegreen_rehearsal.sh` on a disposable Linux box
(WSL works) before production.

**After every deploy:**
1. Self-scan (dogfooding, §2.5): publish a token in `/opt/guardhub/selfverify/guardhub-verify.txt`,
   then `docker run --rm --read-only --cap-drop ALL guardhub-scanner:<sha> selfscan https://guardhub.dev <token>`.
   Exit 0 = no critical/high; 3 = release blocked; 4 = ownership not proven.
2. Live smoke test: `cd e2e && npx playwright test -c playwright.smoke.config.ts` with
   `SMOKE_SSH`, `SMOKE_TOKEN_PATH`, `SMOKE_RAW_SECRET` set (see the spec header). Use an owned
   target only; remove any temporary test site afterwards.

**First admin:** the person registers on the site and enables 2FA, then
`guardhub-ctl.sh exec api python -m guardhub_api.admin.bootstrap promote <email>`.

## 3. Backups and restore drills

- Nightly 03:17 UTC `guardhub-ctl.sh backup`: `pg_dump -Fc` plus a manifest with row counts
  taken in a quiet window, schema version and sha256. Weekly (Sunday 03:47 UTC)
  `guardhub-ctl.sh restore-drill`: restores the newest dump into a throwaway Postgres on an
  internal-only network and **proves** row counts, schema version, RLS, the audit trigger, and that
  encrypted TOTP secrets/evidence decrypt with the production key. Log: `/var/log/guardhub-backup.log`.
- Backups currently live on the same disk. Off-host, encrypted copies are a fast-follow item.
- Redis holds only queues, rate limits, progress and session revocations. Losing it is safe:
  in-flight scans are reaped as `timeout` and users simply rescan.
- Evidence is masked by the scanner and encrypted with `DATA_ENCRYPTION_KEY`.

## 4. Key rotation

| Secret | Rotation effect |
|---|---|
| `JWT_SECRET` | All sessions end, so users log in again. Safe anytime. |
| `HASH_PEPPER` | Rate-limit buckets reset. Unclaimed anonymous scan tokens stop working. |
| `DATA_ENCRYPTION_KEY` | **Don't just replace it**: existing TOTP secrets and evidence would become unreadable. A re-encryption migration is needed (Phase 1 item; see ADR process). |
| DB / Redis passwords | Change in `.env` and in the server (`ALTER ROLE` / `requirepass`), then restart. |

## 5. Incidents

- **Scanner down:** `/admin` shows scanner `down`. Scans stay `queued`, then are reaped as
  `timeout` after the deadline. `docker compose logs scanner`, then restart.
- **Suspected abuse of the free scan:** limits are per IP (5 scans/h) and per target
  (5/h) in `apps/api/guardhub_api/scans/public.py`. The audit log records `target.verified`.
- **Disable a misbehaving check instantly:** `/admin` → Modules → switch it off. New scans skip it.

## 6. Error tracking (Sentry protocol)

Each service is off until its own DSN is set (details: `docs/architecture.md` §7). To turn it on:

1. Use the three Sentry projects (EU region): api (shared by api and api-worker), web, scanner.
   In each project's *Security & Privacy* settings also enable **Prevent Storing of IP
   Addresses** and the default data scrubbers (defence in depth; every service already scrubs).
2. Add to `/opt/guardhub/shared/.env` (never to the repo):
   ```
   SENTRY_DSN_API=https://<key>@o<org>.ingest.de.sentry.io/<api-project-id>
   SENTRY_DSN_WEB=https://<key>@o<org>.ingest.de.sentry.io/<web-project-id>
   SENTRY_DSN_SCANNER=https://<key>@o<org>.ingest.de.sentry.io/<scanner-project-id>
   SENTRY_ENVIRONMENT=production
   COMPOSE_PROFILES=sentry
   ```
   `COMPOSE_PROFILES=sentry` starts `sentry-relay`, the only route api/api-worker have to Sentry
   (they stay on the internal network); its upstream is the host of `SENTRY_DSN_API`
   (`https://o<org>.ingest.de.sentry.io`). `SENTRY_DSN` is only a fallback for an empty
   per-service DSN; leave it empty. Optional: `SENTRY_BROWSER=off` disables browser
   reporting and makes `POST /monitoring` a 404.
3. Pre-pull the relay image and re-activate the running release so every container gets the new
   env (the release tag becomes the Sentry `release`):
   ```bash
   docker pull getsentry/relay:26.4.0
   bash /opt/guardhub/current/ops/deploy/guardhub-ctl.sh activate "$(basename "$(readlink -f /opt/guardhub/current)")"
   ```

**Prove delivery.** Run all four on the server. Each prints the event id and exits 0 only when
the Sentry server (via the relay, for api/api-worker) accepted the event; exit 2 = that service's DSN
is not set; exit 1 = network error or rejected (the message says which). Then search Sentry for
each id (tag `service` = api / api-worker / scanner / web).

```bash
CTL=/opt/guardhub/current/ops/deploy/guardhub-ctl.sh   # exec runs in the ACTIVE colour
$CTL exec api        python -m guardhub_api.common.observability test-event
$CTL exec api-worker python -m guardhub_api.common.observability test-event --service api-worker
$CTL exec scanner    /usr/local/bin/scanner sentry-test
$CTL exec web        node apps/web/scripts/sentry-test.mjs
```

- api/api-worker report `network error` → the relay isn't running (`COMPOSE_PROFILES` missing)
  or can't reach the Sentry host: `docker logs guardhub-sentry-relay-1`.
- `HTTP 400 … invalid project key`, `HTTP 401/403` → wrong DSN (public key or project id).
- Browser reporting has no CLI (no extra public surface): open the site, and in the DevTools
  console run `setTimeout(() => { throw new Error("guardhub browser test") })`. The request to
  `/monitoring` must answer 200 and the event shows up with `runtime=browser`.

**Production setting (2026-11-16): `SENTRY_BROWSER=off`.** `/monitoring` is public: anyone can post
up to the tunnel's rate limit and burn the web project's monthly quota, which would also hide real
web server errors. Before turning browser reporting on, give it its own Sentry project and set a
per-project rate limit (and spike protection) in Sentry. Also enable "Prevent Storing of IP
Addresses" in each project: the relay adds its own internal address as `X-Forwarded-For`.
Delivery was proven on 2026-11-16 from api, api-worker, scanner and web (`test-event` /
`sentry-test` all accepted).
