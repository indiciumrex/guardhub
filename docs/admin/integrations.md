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

## Signed webhooks

An admin adds an HTTPS endpoint (name, address, events). The signing secret is `whsec_...`,
shown once and stored AES-GCM encrypted. Its AAD is the webhook id, and it is re-encrypted by
`ops/rotate_encryption_key`. Migration 0023.

- **Events.**
  - `scan.completed`: only for scans owned by the webhook's owner.
  - `ops_alert.opened`.
  - `ping`: the admin's "Send test".
- **Payload.** Ids, status and counts only. The delivery history keeps the status, attempts,
  HTTP status, error and a SHA-256 of the body, never the body.
- **Signature.** `X-GuardHub-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`.
  Receivers check v1 and that t is within 5 minutes.
- **Retries.** Up to 3 attempts with backoff for network errors, 429 and 5xx. Never for a 4xx or
  a refused address.

### SSRF guards (api-jobs can reach the internet; the host is shared)

- **Address rules.** `https://` only, port 443, a host name. No IP literals, no user info, no
  `localhost`, `.local`, `.internal` or `.lan` names.
- **Resolution.** At delivery time every resolved address must be globally routable. Private,
  loopback, link-local (cloud metadata), CGNAT, unique-local, multicast and IPv4-mapped private
  addresses are all refused. One private answer blocks the whole name.
- **Pinned address.** The request goes to the checked address. The name is used only for TLS SNI,
  the certificate check and the Host header, so DNS cannot change between the check and the
  connection.
- **No redirects.** Redirects are never followed, no proxy settings from the environment are
  used, there is a 10 s timeout, and the response body is not read.
