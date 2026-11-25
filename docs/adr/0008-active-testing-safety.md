# ADR-0008 — Phase 4B: active testing runs on a separate, fenced path

- **Status:** accepted for building and lab measurement. Turning it on for any real or external
  target is a founder decision, after the evidence in §8 has been delivered.
- **Date:** 2026-11-23
- **Context owner:** Phase 4B (active / DAST modules)
- **Touches:** GUARDHUB_STANDARDS §2.3 (do no harm), §2.4 and §9.2 (permission), §9.1 (audit),
  §8.3 (module flags); ADR-0001, ADR-0002, ADR-0003

## Context

Phase 4B adds tests that **send payloads**: reflected XSS, SQL injection, open redirect, SSRF, CORS
origin reflection, and IDOR. Every safety property GuardHub has today assumes passive scanning:

- **The probe client sends only GET and HEAD,** with no body, cookies or credentials
  (`probe/client.go`, `docs/architecture.md` "GET and HEAD only").
- **The scanner trusts the API on ownership.** `runScan` runs no ownership check; only `SelfScan`
  verifies. The API re-proves ownership only when the proof is older than 30 days
  (`projects/scanning.py` `REVERIFY_AFTER`).
- **Missing controls:** there is no kill switch, no global pause, no per-scan cancel, and no record
  of what was sent.
- **Weak backoff:** retries cover only 429 and 503. Nothing slows or stops a scan as other 5xx
  answers pile up.
- **No consent record:** there is no field for the explicit consent §9.2 requires for deep tests.

Active testing must not weaken any of this for passive scans. A bug in an active module must not
reach a target that has not been fenced in.

## Decision

### 1. A separate job kind and client; passive scans are untouched

- **A new job kind.** Active tests run as a new queue job kind, `active_scan` (wire protocol v1,
  ADR-0002, a new `kind` value). The scanner refuses unknown kinds today, so an older scanner
  drops these jobs instead of running them.
- **A separate client.** They use `active.Client`, built on the probe package's dialer and IP
  guard. `probe.Client` stays GET/HEAD-only, and passive checks cannot reach the active client:
  `checks.Target` never carries it.
- **Payloads come only from the reviewed catalogue.** `active.Client` sends only `active.Request`
  values that the payload catalogue builds (§5). There is no API that takes a free-form body or
  URL.
- **A hard scanner switch.** The scanner accepts `active_scan` jobs only when
  `SCANNER_ACTIVE_ENABLED=true`, which is false by default and in production. Without it, the job
  fails with `active_disabled` before any request is sent.

### 2. Scope guard: exact origin, re-proven ownership, recorded consent, every request

- **Ownership, every time.** Before the first request of every active scan, the scanner itself
  re-proves ownership (`verifyOwnership`: well-known file, meta tag or DNS TXT). This includes
  targets the API marks as trusted domains (ADR-0003 is not a bypass here). No proof, no requests:
  the job fails with `ownership_not_verified`.
- **Recorded consent.** The API sends an active scan only for a project with a recorded **active
  testing consent**:
  - who gave it, when, which consent-text version, which origin, and which modules;
  - it is written to the audit log (`project.active_consent`), and revocable at any time.
  - The consent text is legal text and is **not** written by engineering; see §8.
- **Exact scope, on every request.** The scope is the exact origin (scheme, host and port) plus
  optional path prefixes the user excluded.
  - `active.ScopeGuard` checks **every** request, after resolving relative URLs and after each
    redirect hop.
  - Another host, scheme or port, a subdomain, or an excluded path is refused. It never reaches
    the network and is logged as `scope_refused`.
  - Redirects are not followed except same-origin ones, at most 3.
- **The lab exception.** The validation lab skips ownership and consent only for `*.lab.test`
  hosts on the scanner's allowlist. This is the same rule as `ScanLabOrigin`, and it is not a
  configuration option.

### 3. Kill switch

- **Global switch.** The Redis key `gh:active:kill` stops all active testing. The admin sets and
  clears it through an audited endpoint (`active.kill` / `active.resume`).
- **Per-scan switch.** `gh:active:kill:<scan_id>` stops one scan; the user's "stop" button sets it.
- **Checked before every request.** The scanner reads both keys before each request (cached for
  at most 1 s) and checks the job context.
  - Once killed, no further request is sent, and the scan ends as `killed` with its request log.
  - Redis unreachable means killed: the check fails closed.
- **Measured.** The lab measures the time from setting the key to the last request. The target
  is ≤ 2 s; the proof is a test plus a lab run.

### 4. Rate limiter and circuit breaker (do no harm)

- **Rates and budgets:**
  - 1 request per second per host by default, burst 1;
  - at most 300 requests per scan and 100 per module. A spent scan budget stops the scan; a spent
    module budget ends only that check, reported as incomplete (`budget_exceeded`), and the next
    check runs within what is left of the scan budget;
  - one active scan per origin at a time.
- **Backoff on stress:** any 429 or 503 backs off. `Retry-After` is honoured up to 30 s; above
  that, the scan stops.
- **Circuit breaker.** The scan stops (`target_stressed`) on any of:
  - 3 consecutive 5xx answers;
  - a median latency over the last 10 requests above 3× the baseline taken at scan start;
  - any connection failure after the target had answered.
- **Methods: GET only, for now.** Query-string parameters are the only injection point. POST and
  other state-changing requests are out until a separate decision: a POST can store a payload or
  change data even when the test looks harmless.

### 5. Payload catalogue and the do-no-harm review

Every payload lives in one reviewed file, `apps/scanner/internal/active/payloads.go`, with an id,
the module, the exact bytes, and why it is harmless. CI rejects any payload that:

- contains a statement that writes or locks data: `INSERT`, `UPDATE`, `DELETE`, `DROP`,
  `TRUNCATE`, `ALTER`, `CREATE`, `GRANT`, `EXEC`, `xp_`, `INTO OUTFILE`, `LOAD_FILE`, stacked `;`
  queries;
- delays the server (`SLEEP`, `BENCHMARK`, `pg_sleep`, `WAITFOR`). Time-based SQLi is out: it
  holds database connections;
- runs script in a browser by itself. XSS payloads are inert markers: they show whether `<`, `>`
  and `"` come back unencoded in an HTML context, and nothing executes;
- points SSRF or open-redirect probes anywhere but GuardHub's own canary or OOB names (§6). No
  internal addresses or cloud metadata URLs are ever sent;
- is longer than 256 bytes.

**The page's own value (`{orig}`).** A blind SQLi condition must keep the row the page shows,
so the two boolean payloads start with the parameter's own value (`3 AND 7=7` for a page linked
with `id=3`). Only the `active` package fills `{orig}`, from the target URL, and only with a
value of the payload's anchor shape: digits (at most 18) for the numeric payload; letters, digits
and `@ . _ -` (at most 64, no `--`) for the quoted one. Anything else (a quote, a space, `;`, a
parenthesis, a comment, a longer value, no value) becomes `1`, the earlier fixed value. The anchor
is therefore always one literal operand, and the logic sent is only the reviewed text around it;
CI runs the review above on each anchored payload with the fallback and the longest anchor of
its shape. Second review: founder, 2026-11-25.

**Reviews:**

- **New payloads need a second review.** Every new payload is reviewed against this list in its
  PR (the do-no-harm payload review, Gate M).
- **Detection rule:** detection compares the answer to the payload's answer with a baseline and
  with a negative control, a harmless value of the same shape. A difference that also appears
  with the control is not a finding.

### 6. Out-of-band (OOB) harness

- **What it is.** Blind SSRF needs a listener the target can reach: a collaborator that records
  DNS and HTTP interactions for unique, random, per-probe names (`<token>.<oob-domain>`). The
  scanner polls it for its tokens only, and tokens expire after the scan.
- **In the lab:** the lab runs its own collaborator (`oob.lab.test`, DNS and HTTP).
- **For real targets:** this needs a domain and server the founder controls, with DNS
  delegation. That is a founder decision (DNS change, possibly cost), so the SSRF module is
  lab-only until it is made.

### 7. Request log (payload record)

- **Every request is logged,** sent or refused, in `active_request_log`. It is append-only, like
  `audit_logs`, with the same trigger. Each row holds:
  - scan id, module and payload id;
  - method, path, parameter name, and the payload's SHA-256 (the payload is in the catalogue);
  - status, response length, latency;
  - outcome: `sent`, `scope_refused`, `killed`, `budget`, `breaker`.
- **Who sees it:** the user sees it as "what GuardHub sent" for their scan, and the admin sees all
  of it.
- **Retention:** 30 days (founder decision 2026-11-25; was 90 in the first draft). A daily job
  (`purge_active_request_log`, 04:40 UTC) calls `active_request_log_purge()` (migration 0018),
  the only way a row leaves the table: the trigger lets a DELETE through only inside that
  function and only for rows recorded more than 30 days ago. Each purge that removes rows is
  audited (`active_request_log.purged`).
- **Masking:** response bodies are not stored. Evidence follows the existing masking rules.

### 8. What turns active testing on for a real target (founder's checkpoint)

Building, merging and lab-measuring active modules is in scope. They ship **disabled**: module
flags off, `SCANNER_ACTIVE_ENABLED=false`, and no consent UI exposed.

Turning any of it on for a real or external target is the founder's decision, after delivery of:

1. live proof that the scope guard refuses out-of-scope requests and that the kill switch stops
   a running scan within the measured time;
2. the consent, terms and ToS text in Turkish (and English), for legal review. Engineering
   provides the facts (what is sent, how often, what is logged); it does not write the legal
   text;
3. the OOB collaborator infrastructure (domain, DNS, server), if SSRF is wanted.

### 9. Accuracy (Gate M)

Each active module follows ADR-0007's method:

- **Lab:** it is measured on DVWA, OWASP Juice Shop and WebGoat (pinned images), plus small
  look-alike negatives, plus purpose-built lab sites (`test_corpus/active/avlab`, amended
  2026-11-24): the three apps together hold fewer than the gate's minimum of three known
  vulnerabilities for CORS, SSRF and IDOR, and almost no safe look-alikes with real parameters.
  Each av-* site puts known vulnerable lines next to safe look-alikes (encoded, bound, allow-
  listed, owner-checked).
- **Logged in, two accounts:** DVWA, WebGoat and av-idor are measured with two lab accounts
  (ADR-0008 §5), so IDOR and every check behind a login are measured too.
- **Route lists (lab only):** a manifest may list start paths (`start:`) for pages no link
  reaches (Juice Shop's API, WebGoat's lesson endpoints). The oracle gets the same list.
  Production discovery still starts from "/" only; a customer route list would be a later,
  separate decision.
- **Truth:** each app's own documented vulnerability list (DVWA modules, Juice Shop challenges,
  WebGoat lessons; for av-* sites the lines marked VULN in their source), confirmed by an
  independent tool run unmodified in the lab (OWASP ZAP's active scan, pinned, with the pinned
  `ascanrulesBeta` add-on for its CORS and SSRF rules; SSRF is confirmed through ZAP's own
  callback listener on the lab network). ZAP has no IDOR rule: for `active_idor` the documented
  list is the only truth, and the Gate M summary says so.
- **Declared scope:** a real vulnerability a check does not declare (e.g. XSS in a script
  context, a meta-refresh redirect, an allow-list bypass, ORDER BY injection) is listed as
  `outside`: it lowers "recall (all)" in the scorecard, not the gated recall.
- **Gate:** ≥ 95% precision and ≥ 80% recall within each module's declared scope, plus the payload
  review (§5).
- **Measured, not enabled:** a module that passes may be merged and deployed. It stays disabled.

## Consequences

- **Passive scanning is unchanged.** `probe.Client`, its budget and its GET/HEAD rule stay as
  they are.
- **New tables:** `active_consents` and `active_request_log`.
- **New admin endpoint:** the kill switch.
- **New job kind:** `active_scan`.
- **Fail-closed defaults:** a disabled flag, a missing proof, a missing consent, a Redis error or
  an unknown payload all mean nothing is sent.
- **GET-only scope:** stored XSS, POST-only injection points and authenticated areas beyond what
  IDOR needs are out of scope, and the modules' docs say so.
- **IDOR exception:** IDOR needs two accounts the user owns, given as session cookies for the
  scan only, never stored. It is the only module that sends credentials, and only the user's own.
