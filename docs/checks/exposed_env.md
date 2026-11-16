# Check `exposed_env` — exposed secret files

- **Code:** `apps/scanner/internal/checks/exposed_env.go` · tests: `exposed_env_test.go`
- **Category:** exposure · **i18n:** `packages/shared/i18n/<locale>/checks.json` → `exposed_env`

## What it detects

Secret and configuration files that anyone on the internet can download:

| Finding key | Severity | Params | Trigger |
|---|---|---|---|
| `env_file_exposed` | critical | `path`, `secret_count` | a dotenv file is served |
| `git_repository_exposed` | high | `path` | the `.git` directory is readable |
| `cloud_credentials_exposed` | critical | `path` | an AWS credentials file is served |

## Requests sent (all `GET`, in this order)

1. `/guardhub-scanner-404-probe-7f3a9c1e`: the shared soft-404 baseline. Its response is cached per scan, so it costs one request for all checks together.
2. `/.env`, `/.env.local`, `/.env.production`, `/.env.backup`
3. `/.git/HEAD`. `/.git/config` is requested only if `HEAD` was not exposed.
4. `/.aws/credentials`

That is at most 8 requests. Nothing is ever written or posted.

## How it verifies (content signatures, never the status code alone)

A response counts only if **all** of these hold: status 200, non-empty body, the body is **not HTML** (this filters SPA shells and soft-404 pages), and the body is **not byte-identical to the baseline** (this filters catch-all handlers).

- **dotenv:** at least one `KEY=VALUE` line (`^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*\S`), and assignment lines make up at least half of the non-comment lines. `secret_count` is the number of `KEY=VALUE` lines.
- **Git:** `HEAD` is exactly `ref: refs/...` or a 40-hex commit id; `config` contains `[core]`. At most one Git finding is reported.
- **AWS:** a line `aws_access_key_id = ...`.

## Evidence

- Kind `http_response`; location is the full file URL.
- The excerpt has at most 5 non-comment lines plus a `… (N more lines)` marker. **Every value is masked:** values of 9 or more characters keep only their last 4 characters (`DB_PASSWORD=****abcd`), and shorter values are fully masked (`****`). Credentials in URLs (`https://user:token@host`) become `https://****@host`. A test checks that no raw secret ever appears in the serialised finding.

## Plain-language text (en, from the catalog)

- *Title:* "Environment file is publicly downloadable: {path}"
- *Summary:* anyone can download the file, and we counted {secret_count} KEY=VALUE lines, which usually means passwords, API keys or database connection strings.
- *Why:* with these keys someone can read or delete customer data, send email as you, or run up cloud and payment bills.
- *Fix:* 1) **rotate every key and password in the file first**, 2) move the values to the hosting platform's environment settings, 3) block dot-files on the web server (nginx `location ~ /\.` → `deny all`; Apache `RedirectMatch 404 /\..*$`), 4) remove the file from the deployed/public folder and add `.env*` to `.gitignore`, 5) re-scan.

The Git and cloud-credential texts follow the same pattern: rotate first, then block, then remove. See the catalog for the exact wording in `en` and `tr`.

## False-positive risk: low

- SPA/soft-404 sites answer 200 with HTML for every path. They are rejected by the HTML filter and the baseline comparison (tested).
- A plain-text catch-all such as `MAINTENANCE=true` for every path is rejected by the baseline comparison (tested).
- Remaining risk: a deliberately public, non-secret `KEY=VALUE` file at `/.env`. This is very unusual, and it is still a bad practice.

## Why it is do-no-harm

Up to 8 plain GETs of static paths, rate-limited per host, with no parameters, no body, no cookies and no credentials. File contents are never stored unmasked.
