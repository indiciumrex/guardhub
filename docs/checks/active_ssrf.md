# Check `active_ssrf` — server-side request forgery, proven out of band

- **Code:** `apps/scanner/internal/activescan/` · tests: `activescan_test.go`, `idor_test.go`
- **i18n:** `checks.json` → `active_ssrf` (en, tr; the other locales are in the translation queue, §7.5)
- **Module:** ships disabled (migration 0016); active (Phase 4B)
- **Finding key:** `ssrf_confirmed (high)`
- **Decision record:** [ADR-0008](../adr/0008-active-testing-safety.md)

## What it detects

A URL-taking parameter that makes the server fetch an address it is given.

## How it works

Parameters whose name suggests a URL get a unique GuardHub collaborator URL per
probe; a finding needs the collaborator to record a request for that exact token. Nothing
internal is ever addressed. Without a collaborator (`SCANNER_ACTIVE_OOB_URL` empty) the check
does not run.

## Not reported (false-positive discipline)

- reflection of the URL without a server-side fetch;
- fetches the collaborator did not record within the wait.

## Safety (every active check, ADR-0008)

- **Off everywhere** until the founder's checkpoint (ADR-0008 §8): the scanner refuses
  `active_scan` jobs unless `SCANNER_ACTIVE_ENABLED=true`, and the admin refuses to switch an
  active module on unless `ACTIVE_TESTING_APPROVED` is set (migration 0016 registers it disabled).
- **Scope:** exactly the verified origin, ownership proven again at the start of every scan
  (trusted domains included) and a recorded consent (`active_consents`); excluded paths honoured.
- **Fences** (`internal/active`): kill switch (`gh:active:kill[:scan]`, fail-closed), 1 request/s,
  300 requests per scan and 100 per module, circuit breaker (3x 5xx, 3x baseline latency, long
  Retry-After), GET only, at most 3 same-origin redirects, every request in the append-only
  `active_request_log`.
- **Payloads** come only from the reviewed catalogue (`internal/active/payloads.go`); its test
  rejects data-changing SQL, delays, self-executing markup, internal addresses and long values.
- **Discovery** (`internal/activescan/discover.go`) follows same-origin links and GET forms from
  `/`; it never requests logout/state-changing links (delete, pay, reset, ...), never submits a GET
  form with a password field or a change-naming submit, and skips static files.

## Validation (Gate M)

`test_corpus/active/run.sh`: `scanner activelab` (the production path) on DVWA, Juice Shop,
WebGoat and passive lab targets as false-positive controls; ground truth in
`test_corpus/active/manifests`, confirmed by OWASP ZAP 2.17.0 (pinned by digest,
`test_corpus/oracles/zap`). Scorecards: `docs/accuracy-active/`.
