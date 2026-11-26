# Observe-only scans without an ownership proof (super-admin): built, OFF

Code: `apps/api/guardhub_api/admin/observe.py`, scanner job kind `observe_scan`
(`apps/scanner/internal/queue/jobs.go`), page `/admin/observe`.

## The boundary

Without an ownership proof, a scan can only **observe**: it sees what any browser or mail server
sees. The set is defined once, in `packages/shared/check-ids.json` (`"observe": true`), and
generated into the API, the scanner and the web app.

| Runs without a proof (observe-only) | Why it is observation |
|---|---|
| `tls_cert`, `tls_config`, `tls_depth` | TLS handshakes and one GET of `/`, as any browser |
| `security_headers`, `header_quality`, `cookie_depth` | the response headers of one GET of `/` |
| `http_hardening` | GET `/`, plus at most two GETs of `/` with an `Origin` header (what browsers send) |
| `content_signals`, `js_libraries` | the home page's HTML and the same-origin scripts it loads; version lookups at OSV |
| `dns_depth` | public DNS records; the MTA-STS policy file every mail server fetches |

| Needs a verified site, always (no exception, no override) | Why |
|---|---|
| `exposed_env`, `exposed_files`, `open_admin`, `info_leak` | request paths the site does not link to (path probing) |
| `default_creds` | tries sign-in credentials |
| `dns_email` | sends a recursion question and an AXFR (zone transfer) request to the nameservers |
| `subdomain_takeover` | enumerates names under the host (Certificate Transparency + DNS) |
| `js_secrets` | collects credentials the site ships |
| every active check (`active_*`) | payloads; also behind all active-test locks (ADR-0008) |

## How it is enforced

1. **Who:** an admin (role re-read from the database, full two-factor session) whose user id is
   in `SUPER_ADMIN_IDS` on the server. Everyone else gets 404.
2. **Switch:** `OBSERVE_SCAN_ENABLED` on the server, `false` by default.
3. **Statement:** every scan needs the current authorisation statement (version + SHA-256),
   the relationship to the site (owner / client / employer / other) and a note of at least 10
   characters. All of it goes to the audit log (`admin.observe_scan.declared`) **before** the scan
   is queued; `admin.observe_scan.queued` follows with the scan id.
4. **API boundary:** a request that names any check outside the observe-only set is refused
   (422 `ownership_required`). Private and internal addresses are refused as everywhere else.
5. **Scanner boundary (defence in depth):** the job goes out as `observe_scan`. The scanner
   rejects the whole job if it lists no checks or any check that is not observe-only, so a bug in
   the API cannot widen what an unproven target receives.
6. **Record:** the scan carries `trigger = 'observe'`, no project, and belongs to the admin.
   Rate limit: 10 per hour per admin.

Nothing here touches §9.2 for anything else: project scans, trusted domains, owner and customer
active scans keep every lock they had.

## Going live (the founder's decision)

1. Approve the boundary above.
2. Set `SUPER_ADMIN_IDS=<founder's user id>` and `OBSERVE_SCAN_ENABLED=true` in the server `.env`.
3. Recreate the serving colour's API, then re-run gates A–K.

To roll back, set `OBSERVE_SCAN_ENABLED=false`, or empty `SUPER_ADMIN_IDS`; either one alone
stops new observe-only scans.

## Conditions set at go-live (2026-11-26)

- **Passive rate limit.** An `observe_scan` job runs through the same `runScan` path as every
  passive scan: a fresh `NewScanProbe` client with the shared per-host limiter
  (`SCANNER_HOST_RPS`, `SCANNER_HOST_BURST`) and the per-scan request budget
  (`SCANNER_MAX_REQUESTS_PER_SCAN`). There is no separate or faster path.
- **Labelled report.** Every report of an observe scan carries an "Observational scan" badge
  under the heading and a notice that ownership was not proven and that no active, path-probing
  or login check ran (live view, final report and print). Admin scan lists and trend charts
  show the trigger as "Observational".
- §9.2 and the active-testing locks are unchanged: any non-observe check is refused with
  `ownership_required`, and the scanner rejects an `observe_scan` job that lists one.
