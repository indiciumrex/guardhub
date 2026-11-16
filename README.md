# GuardHub

**A simple, continuous security watchdog for founders who aren't security experts.**
Enter your site's address, watch each check run, and get a plain-language report
(*what's exposed → why it matters → how to fix it*) in your own language.

GuardHub · `guardhub.dev` · Powered by **HKSolutions**

> The single source of truth for architecture, rules and process is
> [`GUARDHUB_STANDARDS.md`](GUARDHUB_STANDARDS.md). The wire contracts between services are in
> [`docs/architecture.md`](docs/architecture.md), and decisions are recorded in [`docs/adr/`](docs/adr).

## Quick start (local, one command)

Requirements: Docker (with Compose v2) and Python 3.12+ (only to generate secrets).

```bash
python ops/scripts/gen_secrets.py        # writes .env with strong random secrets (never commit it)
docker compose up --build                # web, api, api-worker, scanner, redis, postgres
```

Open <http://localhost:3000>. The site opens in your browser's language (9 languages are
supported, and `en` and `tr` are fully translated). Switch languages from the navbar.

### Try a full scan locally (deliberately vulnerable demo target)

```bash
python ops/scripts/gen_secrets.py --force --demo
docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build
```

Scan `http://demo-target:8080` from the free-scan page. To prove ownership, put the token
it shows into `ops/demo-target/site/.well-known/guardhub-verify.txt`, then click
**Verify & start scan**. `ops/scripts/e2e_demo.py` automates the whole loop.

## How a scan works

```
Enter URL → prove ownership (file / meta tag / DNS TXT) → scanner runs 6 passive checks
→ live progress per check → plain-language report + score → (sign up) save & rescan
```

- **Permission first ([ADR-0001](docs/adr/0001-anonymous-scan-requires-ownership-proof.md)):** we only scan targets whose owner has proven control,
  even for the free scan without registration.
- **Do no harm:** GET/HEAD only, rate-limited per host, a request budget per scan, timeouts,
  and an anti-SSRF IP guard at dial time ([architecture §3](docs/architecture.md#3-scanner-safety-envelope-92-do-no-harm--enforced-in-scannerinternalprobe)).
- **The six MVP checks** (one doc page each in [`docs/checks/`](docs/checks)): `exposed_env`, `security_headers`,
  `tls_cert`, `open_admin`, `default_creds` (passive; never submits credentials), `info_leak`.

## Accounts, 2FA and admin

- Sign-up is only needed to **save, rescan and keep history**. Two-factor authentication
  (TOTP) is **mandatory** before the dashboard opens (§9.1).
- No HTTP route can grant admin. An operator promotes an existing 2FA-enabled user:
  ```bash
  docker compose exec api python -m guardhub_api.admin.bootstrap promote you@example.com
  ```
- Admin (`/admin`): module on/off switches, users, scans, system health, audit log, and AI seam
  status (no-op: the core never needs AI).

## Repository map

| Path | What |
|---|---|
| `apps/api` | FastAPI orchestration: auth, projects, scans, findings (plain language), admin, health, AI seam |
| `apps/scanner` | Go scanning engine: worker pool, safe probe client, checks, live progress |
| `apps/web` | Next.js UI: landing, free scan, account, admin (brand on every screen) |
| `packages/shared` | Single-source contracts: `finding.schema.json`, `check-ids.json`, `i18n/`, `brand/` |
| `ops/migrations` | PostgreSQL schema + Row-Level Security (Alembic, raw SQL) |
| `ops/ci`, `.github/workflows` | Quality gates: lint → tests → secret scan → schema sync → i18n |
| `docs/` | Architecture, ADRs, per-check docs, runbooks |

## Development

```bash
# contracts: regenerate Python/Go/TS types after editing packages/shared
python packages/shared/scripts/gen_types.py
python ops/ci/check_i18n.py

# api
cd apps/api && uv sync && uv run ruff check . && uv run mypy guardhub_api && uv run pytest
# api integration tests need a migrated Postgres + Redis (see apps/api/tests/integration/conftest.py)

# scanner
cd apps/scanner && go vet ./... && go test -race ./...

# web
cd apps/web && npm ci && npm run lint && npm test && npm run build
```

## Security posture (summary)

- Secrets come only from the environment. The app refuses to boot with placeholder or weak
  values, and CI runs gitleaks.
- PostgreSQL Row-Level Security: the API's DB role isn't the table owner, so a missing
  `WHERE` can't leak another user's data. The audit log is append-only at the database level.
- TOTP secrets and evidence are encrypted at rest (AES-256-GCM). Client IPs and scan tokens
  are stored only as keyed hashes.
- Session JWTs are in `HttpOnly; Secure; SameSite=Strict` cookies, with a CSRF header required
  on every state change, server-side revocation on logout, and TOTP replay protection.
- Network isolation in Compose: Postgres, Redis and the API have no internet access. Only the
  scanner has egress, and its IP guard refuses private addresses.

See [`ops/runbooks/`](ops/runbooks) for operations (deploy behind TLS, backups, key rotation).
