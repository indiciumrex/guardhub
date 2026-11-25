# API keys, the integration API and endpoint traffic

Admin → API & integrations (`/admin/integrations`).

## API keys

- **Format.** `ghk_` plus 32 random bytes, shown once at creation. Only a keyed hash (pepper)
  and a 12-character prefix are stored (migration 0022).
- **Scopes.** `projects:read`, `scans:read`, `scans:trigger`. Every key expires after 30, 90, 180
  or 365 days and can be revoked at any time. A key allows 120 requests a minute.
- **Audit.** `api_key.created` and `api_key.revoked`. A scan started with a key records actor
  `apikey:<id>`.

## Boundaries (enforced in code, covered by integration tests)

- **Never a session.** A key never produces a session (`SessionClaims`). Every cookie-session
  route, the admin API included, ignores the `Authorization` header and answers 401.
- **User role only.** A key acts as its owner in the **user** database role (RLS), even when the
  owner is an admin. It sees the owner's own projects and scans only.
- **Ownership proof still applies.** A scan started with a key goes through
  `start_project_scan`, which re-checks ownership proof (§9.2) exactly as a manual re-scan does.
- **No active tests.** Active tests cannot be started with a key.

## Integration API

Send `Authorization: Bearer ghk_...`. Requests that change state also need `X-GuardHub-CSRF: 1`.

| Route | Scope |
|---|---|
| `GET /api/v1/integrations/projects` | `projects:read` |
| `GET /api/v1/integrations/scans/{scan_id}` | `scans:read` |
| `POST /api/v1/integrations/projects/{project_id}/scans` | `scans:trigger` (rate limit as a manual re-scan) |

## Endpoint traffic

The request middleware records, per route template (`GET /api/v1/scans/{scan_id}`, never raw
identifiers or query strings):
- requests;
- 4xx, 5xx and 429 responses;
- a latency sum and histogram.

The data lives in hourly Redis hashes kept for 48 h, and recording never raises. The admin page
shows the last 1, 24 or 48 hours with the average latency and an approximate p95 (the upper
bound of the histogram bucket).

Signed webhooks follow in their own PR.
