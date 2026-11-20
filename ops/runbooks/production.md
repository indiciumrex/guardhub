# Runbook — running GuardHub in production (guardhub.dev)

## 1. Where it runs (shared host)

guardhub.dev runs on a **shared** Ubuntu host next to other projects. Rules: touch nothing outside
`/opt/guardhub`, the compose project `guardhub`, `/etc/nginx/sites-enabled/guardhub.dev.conf`,
`/etc/cron.d/guardhub-backup` and the `guardhub.dev` certbot renewal file.

| Path | What |
|---|---|
| `/opt/guardhub/releases/<sha>` | one directory per release (git archive of that commit) |
| `/opt/guardhub/current`, `previous` | symlinks used by deploy/rollback |
| `/opt/guardhub/shared/.env` | production secrets, `root:root 600`, generated on the server; **keep an offline copy of `DATA_ENCRYPTION_KEY` (+ any `DATA_ENCRYPTION_KEYS_PREVIOUS`) and `RESTIC_PASSWORD`** (backups are useless without them) |
| `/opt/guardhub/backups` | `pg_dump -Fc` + manifest, 14-day retention (`700`); copied off-site, encrypted, by restic (§3.1) |
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
1. pre-deploy backup: the LOCAL dump is mandatory (activate stops if it fails); the off-site
   copy then runs in the background (§3);
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
  taken in a quiet window, schema version and sha256, then (when configured) the encrypted
  off-site copy (§3.1). Without off-site config the log says `offsite: not configured` and
  `status` shows it; that is not an error, but production must have it.
- Weekly (Sunday 03:47 UTC) restore drill: from the newest **off-site** snapshot when off-site is
  configured (`restore-drill --offsite`), otherwise from the newest local dump. It restores into a
  throwaway Postgres on an internal-only network and **proves** row counts, schema version, RLS,
  the audit trigger, and that every encrypted column (TOTP secrets, evidence, Slack webhooks)
  decrypts with the keyring (`DATA_ENCRYPTION_KEY`, then `DATA_ENCRYPTION_KEYS_PREVIOUS`); it
  prints how many values are still `under_previous_key`. Log: `/var/log/guardhub-backup.log`.
- Pre-deploy/rollback backups (`activate`, `rollback`, or by hand: `guardhub-ctl.sh
  predeploy-backup`): the local dump is mandatory and taken first; the off-site copy is
  **best-effort and asynchronous** (detached, at most `OFFSITE_PUSH_TIMEOUT`=1800 s), so a storage
  outage never blocks or slows a deploy. Its outcome is the `offsite pre-deploy copy:` line of
  `guardhub-ctl.sh status` (`queued | running | ok | FAILED`), with details in
  `/opt/guardhub/state/offsite-predeploy.log`. A FAILED copy is not urgent: the local dump
  exists and the nightly backup pushes the newest dump again; if it keeps failing, run
  `offsite.sh check`. All pushes (nightly, manual, pre-deploy) share one lock
  (`state/offsite.lock`), because retention (`forget --prune`) needs the repository exclusively.
- Redis holds only queues, rate limits, progress and session revocations. Losing it is safe:
  in-flight scans are reaped as `timeout` and users simply rescan.
- Evidence is masked by the scanner and encrypted with `DATA_ENCRYPTION_KEY`.

### 3.1 Off-site backups (restic, encrypted client-side)

`ops/deploy/offsite.sh` runs the official `restic/restic:0.19.1` image (pinned by digest) with
`docker run --rm`; nothing is installed on the host. restic encrypts and authenticates
everything **before** it leaves the server (AES-256 + Poly1305), so the storage provider only
ever sees ciphertext. Each nightly snapshot holds one dump plus its manifest; retention is
`restic forget --keep-daily 14 --keep-weekly 8 --prune` after every push (about 8 weeks of
history). Secrets reach the container as `-e NAME` only (never in `ps`), and only the variables
below: the restic container never sees GuardHub's own secrets.

**Provision once:**
1. An S3-compatible bucket at a different provider or region than this host, private, used for
   nothing else. Turn on **versioning** with a lifecycle rule that deletes non-current versions
   after ~30 days (or object lock in governance mode): then a stolen server key that deletes
   objects can't destroy the history.
2. An access key **restricted to that bucket** (list/get/put/delete on it, nothing else in the
   account).
3. A restic password, generated offline: `head -c 32 /dev/urandom | base64`. Store it **offline
   next to `DATA_ENCRYPTION_KEY`** (password manager + a sealed paper copy). Without it the
   off-site backups are unreadable, by us too; restic cannot recover it.
4. Put them in their own file, `/opt/guardhub/shared/offsite.env` (owner root, mode 600), with
   an editor (not `echo`: shell history). Not in `.env`: docker compose reads `.env` and expands
   `$...` inside values, and a strong password may contain `$`. Values are read literally (no
   quotes, no escaping). If `offsite.env` doesn't exist, `offsite.sh` falls back to `.env`.
   ```
   RESTIC_REPOSITORY=s3:https://<s3-endpoint>/<bucket>/guardhub
   RESTIC_PASSWORD=<from step 3>
   AWS_ACCESS_KEY_ID=<bucket-scoped key id>
   AWS_SECRET_ACCESS_KEY=<bucket-scoped secret>
   AWS_DEFAULT_REGION=<region, optional>
   ```
5. Initialise and prove it, then install the cron file (it runs the scripts with `bash`):
   ```bash
   D=/opt/guardhub/current/ops/deploy
   docker pull restic/restic:0.19.1@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510
   bash $D/offsite.sh init
   bash $D/guardhub-ctl.sh backup                  # local dump + "offsite: pushed ..."
   bash $D/guardhub-ctl.sh restore-drill --offsite # must end with RESTORE DRILL PASSED
   bash $D/guardhub-ctl.sh status                  # last line: offsite: configured, latest snapshot ...
   install -m 644 $D/guardhub-backup.cron /etc/cron.d/guardhub-backup
   ```
Monthly: `bash $D/offsite.sh check` (repository integrity). A push that dies mid-way can leave a
stale lock: `bash $D/offsite.sh unlock`. `ops/deploy/tests/offsite_e2e.sh` proves the whole flow
locally (MinIO + throwaway Postgres; wrong password fails; no plaintext in the bucket).

### 3.2 Restore from off-site only (server lost)

Needs only the offline copies: `DATA_ENCRYPTION_KEY` (+ `DATA_ENCRYPTION_KEYS_PREVIOUS` if a key
rotation happened within the last ~8 weeks), `RESTIC_PASSWORD`, the bucket key, and access to
this repository.
1. New host per §1 (Docker, nginx vhost, UFW) and point DNS at it (certbot needs it for the
   certificate). Between steps 3 and 5 the site is up but EMPTY: anything created then is
   overwritten in step 5, so keep that window to minutes.
2. Write `/opt/guardhub/shared/.env` (`root:root 600`): start from `.env.example` +
   `python3 ops/scripts/gen_secrets.py` for the database/Redis/JWT/pepper values (new ones are
   fine; a new `JWT_SECRET` only logs everyone out, a new `HASH_PEPPER` only resets rate limits
   and unclaimed anonymous scan tokens), then put back from the offline store:
   `DATA_ENCRYPTION_KEY`, `DATA_ENCRYPTION_KEYS_PREVIOUS`, the `RESTIC_*`/`AWS_*` values,
   `PUBLIC_BASE_URL`, and keep `GUARDHUB_APP_DB_USER` at the old name (the dump's grants use it).
3. `ops/deploy/deploy.sh root@<new-host>` (from a workstation, same commit as before or newer).
   This starts an EMPTY GuardHub (fresh schema).
4. Fetch, verify and **prove** the newest off-site backup before using it:
   ```bash
   D=/opt/guardhub/current/ops/deploy
   DUMP=$(bash $D/offsite.sh restore-latest /opt/guardhub/backups/from-offsite)  # sha256 checked
   bash $D/guardhub-ctl.sh restore-drill "$DUMP"   # must end with RESTORE DRILL PASSED
   ```
5. Load it into the production database (app containers stopped, data layer running):
   ```bash
   docker ps --format '{{.Names}}' | grep -E '^guardhub-(blue|green)-' | xargs -r docker stop
   U=$(grep -E '^POSTGRES_USER=' /opt/guardhub/shared/.env | cut -d= -f2-)
   DB=$(grep -E '^POSTGRES_DB=' /opt/guardhub/shared/.env | cut -d= -f2-)
   docker exec guardhub-postgres-1 psql -U "$U" -d postgres -c "DROP DATABASE \"$DB\"" -c "CREATE DATABASE \"$DB\""
   docker exec -i guardhub-postgres-1 pg_restore -U "$U" -d "$DB" --no-owner --exit-on-error <"$DUMP"
   bash $D/guardhub-ctl.sh activate "$(basename "$(readlink -f /opt/guardhub/current)")"
   ```
   (`activate` runs the release's migrations: a no-op at the same schema, an upgrade if newer.)
6. Check: log in with a real account + 2FA (TOTP decrypts), open an old report (evidence
   decrypts), `guardhub-ctl.sh status`. Then take `guardhub-ctl.sh backup`, install
   the cron file (§3.1 step 5) and delete `/opt/guardhub/backups/from-offsite`.

## 4. Key rotation

| Secret | Rotation effect |
|---|---|
| `JWT_SECRET` | All sessions end, so users log in again. Safe anytime. |
| `HASH_PEPPER` | Rate-limit buckets reset. Unclaimed anonymous scan tokens stop working. |
| `DATA_ENCRYPTION_KEY` | **Never just replace it**: existing TOTP secrets, evidence and Slack webhooks would become unreadable. Follow §4.1. |
| `RESTIC_PASSWORD` | Only wraps restic's master key: `restic key add` then `restic key remove <old id>` (not scripted). Store the new one offline first. |
| DB / Redis passwords | Change in `.env` and in the server (`ALTER ROLE` / `requirepass`), then restart. |

### 4.1 Rotating DATA_ENCRYPTION_KEY

The app keeps a **keyring**: `DATA_ENCRYPTION_KEY` is the current key (all new encryption);
`DATA_ENCRYPTION_KEYS_PREVIOUS` (comma-separated base64 keys, newest first, validated at
startup like the current key) is used **only to decrypt**. AES-GCM is authenticated, so trying
the keys in order is safe; a value no key opens is an error, never ignored. The CLI
`python -m guardhub_api.ops.rotate_encryption_key [--dry-run] [--batch-size N]` re-encrypts
every encrypted column (`users.totp_secret`, `evidence.redacted_payload`,
`notification_settings.slack_webhook_enc`) under the current key: batches of N rows (default
500) in their own transactions, values already under the current key are skipped (a re-run is a
no-op), each rewritten value is read back and checked before commit, and if any value can't be
decrypted its whole batch is left untouched and the exit code is 1. It is audited as
`ops.encryption_key_rotated` (counts only). No downtime: the app reads both keys throughout.

Prerequisites: the running release contains the keyring (do not rotate while a rollback to an
older release is still possible: it would not know `DATA_ENCRYPTION_KEYS_PREVIOUS`), and the last
restore drill passed.

1. **Generate the new key offline** (a trusted workstation, not the server):
   `head -c 32 /dev/urandom | base64`. Store it in the offline secret store **before** anything
   else, labelled with the date; the old key stays there too.
2. Fresh backup under the old key: `bash $D/guardhub-ctl.sh backup` (`D=/opt/guardhub/current/ops/deploy`).
3. Edit `/opt/guardhub/shared/.env` with an editor (never `echo`: shell history):
   ```
   DATA_ENCRYPTION_KEY=<NEW key>
   DATA_ENCRYPTION_KEYS_PREVIOUS=<OLD key>          # if it already had keys: <OLD>,<older>
   ```
4. Deploy the new env with zero downtime (same release into the idle colour):
   `bash $D/guardhub-ctl.sh activate "$(basename "$(readlink -f /opt/guardhub/current)")"`.
   From now on new values use the NEW key; old ones are still read with the OLD key.
5. Re-encrypt (after `activate` finished, so no old-colour container writes with the old key):
   ```bash
   bash $D/guardhub-ctl.sh exec api python -m guardhub_api.ops.rotate_encryption_key --dry-run
   bash $D/guardhub-ctl.sh exec api python -m guardhub_api.ops.rotate_encryption_key
   ```
   The dry run must show `undecryptable=0` on every line; the real run must end with
   `OK: every encrypted value is under the current key` (exit 0). Exit 1 lists each undecryptable
   row; their batches were not changed. Do **not** remove any key: find the key those rows were
   written with, add it to `DATA_ENCRYPTION_KEYS_PREVIOUS`, re-activate, run again.
6. Verify: `bash $D/guardhub-ctl.sh backup`, then `bash $D/guardhub-ctl.sh restore-drill` (and
   `--offsite` if configured) must PASS with `under_previous_key=0`. The audit log (`/admin`)
   shows `ops.encryption_key_rotated` with `result=ok`.
7. **Keep `DATA_ENCRYPTION_KEYS_PREVIOUS` for the backup retention window**: dumps taken before
   step 5 hold values under the OLD key (local copies 14 days, off-site weekly snapshots ~8
   weeks). After 8 weeks remove the old key from `DATA_ENCRYPTION_KEYS_PREVIOUS`, re-activate
   (step 4) and run a drill. Keep the old key in the offline store until the last off-site
   snapshot older than the rotation has been pruned (`offsite.sh check` lists the snapshots);
   to restore such a backup later, put the old key back into `DATA_ENCRYPTION_KEYS_PREVIOUS`.
   *Rotating because the old key leaked?* Then do step 7 right after step 6 (the old key is no
   longer needed by the live app) and use the offline copy only for old backups.
8. Offline store: it must always hold the current key, every key still listed in
   `DATA_ENCRYPTION_KEYS_PREVIOUS`, and `RESTIC_PASSWORD`.

**Rollback** (any time, before or after step 5): the same mechanism in reverse, never by deleting
the new key (values written since step 4 are under it). Set `DATA_ENCRYPTION_KEY=<OLD>` and
`DATA_ENCRYPTION_KEYS_PREVIOUS=<NEW>`, re-activate (step 4), run the CLI (step 5): everything is
back under the old key. The keyring decrypts both throughout, so users notice nothing.

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

## 7. Trusted domains (ADR-0003)

Admins can prove a host once at `/admin/trusted-domains` and then scan exactly that origin
(same scheme, host and port; never subdomains) without the proof prompt. Operator notes:

- **Re-check job:** `recheck_trusted_domains` (api-jobs, daily 04:10 UTC) re-runs the verify job
  for every `active` and `suspended` domain, at most 2 at a time. Proof gone → `suspended`, back →
  `active`; both are audited as `admin.trusted_domain.{suspended,reactivated}` with actor
  `system:trusted-domain-recheck`. A queue outage leaves domains untouched (counted as `errors`).
- **If the job stops running,** trust lapses on its own: a domain only counts while its last
  successful proof is under 30 days old. Admins then see `trusted_domain_inactive`, or "Scan now"
  re-proves inline. Nothing is ever scanned on an old proof.
- **Who has what:** `SELECT a.email, d.host, d.status, d.verified_at, d.last_checked_at,
  d.last_check_error FROM admin_trusted_domains d JOIN users a ON a.id = d.admin_user_id
  WHERE d.status <> 'revoked';` (owner role; the app role only sees its own rows via RLS).
- **Emergency stop for one domain:** have the admin remove it in the UI. If that's not possible,
  `UPDATE admin_trusted_domains SET status = 'revoked', revoked_at = now() WHERE id = '<id>';`
  as the owner role, and note why in the incident log (the audit log is append-only and is
  written by the app, not by manual SQL).
- **Demoting an admin** (`python -m guardhub_api.admin.bootstrap demote <email>`) disables their
  trusted domains at once: the role is re-read from the database on every request.
