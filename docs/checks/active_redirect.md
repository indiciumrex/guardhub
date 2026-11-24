# Check `active_redirect` — open redirect to an unreachable canary host

- **Code:** `apps/scanner/internal/activescan/` · tests: `activescan_test.go`, `idor_test.go`
- **i18n:** `checks.json` → `active_redirect` (en, tr; the other locales are in the translation queue, §7.5)
- **Module:** ships disabled (migration 0016); active (Phase 4B)
- **Finding key:** `open_redirect (medium)`
- **Decision record:** [ADR-0008](../adr/0008-active-testing-safety.md)

## What it detects

A parameter that sends the browser to any absolute or protocol-relative URL.

## How it works

The parameter gets `https://gh-canary.invalid/` or `//gh-canary.invalid/`
(`.invalid` never resolves). A finding needs a `Location` (or `Refresh`) pointing at that
host. The redirect is never followed.

## Not reported (false-positive discipline)

- redirects to the site itself or to an allow-listed host;
- the canary only echoed in the page body.

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
