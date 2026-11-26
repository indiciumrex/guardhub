# Active tests on customer sites (Phase 5B): built, OFF

Code: `apps/api/guardhub_api/active/customer_scan.py`, routes `/api/v1/projects/{id}/active…`,
panel "Active testing (beta)" on the customer's project page.

## Nothing goes out until every lock holds

The locks are checked in this order, on every request:

| # | Lock | Where | Today |
|---|---|---|---|
| 1 | The founder's go | `CUSTOMER_ACTIVE_TESTING_GO=true` (server `.env`) | not set: **off** |
| 2 | Final, published terms | `ACTIVE_TOS_VERSION` + `ACTIVE_TOS_SHA256` (SHA-256 of the exact published text) | not set: **draft** |
| 3 | SSRF only: live OOB collaborator | a scanner reports `active_oob`. Without it SSRF is not offered, a request for it is refused (`oob_not_configured`), and the panel and the report say "SSRF is not covered in this plan". The other modules do not need it. | **none**: SSRF not covered |
| 4 | Founder approval of active testing | `ACTIVE_TESTING_APPROVED` | on (owner targets) |
| 5 | Every requested module on | Module Center | 5 on, SSRF off |
| 6 | Kill switch released | Scans → kill switch (an unreadable switch counts as engaged) | released |
| 7 | Scanner switch | `SCANNER_ACTIVE_ENABLED` | on |
| 8 | The customer's own site, with a fresh §9.2 proof | re-proven if stale; the scanner proves it again at scan start | per site |
| 9 | The customer accepts exactly the current terms version | `active_consents` row (version + SHA-256) per scan | per scan |
| 10 | One active scan per site | origin lock | always |

## The three operating preconditions, enforced

1. **One active scan per site at a time.** Origin lock (10).
2. **The request log is deleted after 30 days.** Migration 0018, daily purge at 04:40 UTC.
3. **The customer's own "Stop now" for a running scan.** It sets the per-scan kill key, which the
   scanner honours within about a second. Only the site's owner can stop it; another account
   gets 404.

The scope guard, budgets, GET-only requests, 1 request a second and the global kill switch
(ADR-0008) apply unchanged: the scan runs through the same scanner path as owner-target scans.
IDOR is not offered to customers (it needs test-account cookies).

## Going live (the founder's gate; nothing here is done without the founder's "go")

1. Publish the active-testing terms at `/legal/active-testing`. Set `ACTIVE_TOS_VERSION` and
   `ACTIVE_TOS_SHA256` to that exact text's version and hash. GuardHub does not write legal text.
2. Set `CUSTOMER_ACTIVE_TESTING_GO=true`.
3. Recreate the serving colour's api and scanner, then re-run gates A–K.

The OOB collaborator is no longer a go-live step: it only adds SSRF later (deploy it, verify the
scanner reports `active_oob`, switch the SSRF module on).

To roll back, remove either the go or the terms; each one alone blocks every new customer active
scan. The
global kill switch stops running scans.
