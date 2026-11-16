# Runbook — running GuardHub in production (guardhub.dev)

## 1. TLS in front of `web` (required, §9.1: TLS 1.3 in transit)

Compose publishes only `web:3000`. Put a TLS-terminating reverse proxy in front of it and expose
**only** ports 80/443. Example with Caddy (automatic certificates, TLS 1.3, HTTP→HTTPS):

```caddy
guardhub.dev {
  tls { protocols tls1.3 }
  encode zstd gzip
  reverse_proxy 127.0.0.1:3000
}
www.guardhub.dev { redir https://guardhub.dev{uri} permanent }
```

Then set in `.env`: `PUBLIC_BASE_URL=https://guardhub.dev`, `COOKIE_SECURE=true`, and
`TRUSTED_PROXY_HOPS=2` (Caddy + the web rewrite both append `X-Forwarded-For`). If this
value is wrong, per-IP rate limits apply to the proxy instead of the client.

## 2. First deploy

1. `python ops/scripts/gen_secrets.py` on the server, then store `.env` in your secret manager
   and keep the file `chmod 600`. Keep `SCANNER_ALLOW_PRIVATE_HOSTS` **empty**.
2. `docker compose up -d --build`. `migrate` runs Alembic as the owner role, then exits.
3. Register your account on the site and enable 2FA, then promote it:
   `docker compose exec api python -m guardhub_api.admin.bootstrap promote you@hksolutions…`
4. Check `/admin` → System health: database, redis and scanner should all be `ok`.
5. **Dogfooding (§2.5, §9.1):** run `python ops/scripts/self_scan.py https://guardhub.dev`
   before each release. Any critical/high finding blocks the release.

## 3. Backups and data

- PostgreSQL volume `pgdata`: take a nightly `pg_dump -Fc` as the owner role and store it
  encrypted off-host. Test a restore monthly.
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
