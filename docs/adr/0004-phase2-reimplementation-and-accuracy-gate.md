# ADR-0004 — Phase 2: re-implement the deep checks in Go, measure every check, gate enabling on accuracy

- **Status:** accepted
- **Date:** 2026-11-22
- **Context owner:** Phase 2 ("Derinlik ve İsabet")

## Context

Phase 2 deepens TLS and header/cookie analysis and adds DNS/e-mail security and subdomain
takeover. The prompt points to engines in a separate project (`websecurityscanner`: Rust
`tls_analyzer`; Go `http_probe`, `dns_analyzer`, `subdomain_enumerator`), described as already
tested. It says to adapt them rather than copy blindly, and to leave their known defects behind.

A read-only review of all four (file:line findings kept in the session notes) showed they cannot
be adapted safely:

- **`tls_analyzer` (Rust).**
  - The "export" probe offers AES-128 too, so any normal server is reported as accepting export
    suites (High FREAK).
  - The TLS 1.3 probe cannot negotiate TLS 1.3, and the SSLv2 probe is a copy of the SSLv3 one.
  - Certificate checks are never wired in.
  - Ticketbleed reports every server.
  - It contains an exploit-style Heartbleed probe.
- **`http_probe`.**
  - By default it sends PUT, DELETE, TRACE, PROPFIND, an IIS `DEBUG stop-debug` and a POST to
    `/forgot-password`. That breaks §2.3 and §9.2.
  - CSP analysis is substring matching, and every cookie gets Medium findings.
- **`dns_analyzer`.**
  - "Zone transfer open" is High whenever a domain has more than 10 TXT records; no AXFR is sent.
  - "DNSSEC" searches TXT records for the word "dnssec".
  - `caa_missing` fires on every domain, and errors become "missing".
- **`subdomain_enumerator`.**
  - Any CNAME to a provider is High. NXDOMAIN is never checked, and dangling CNAMEs are dropped
    before the takeover check.
  - It brute-forces 143k names (about 287k DNS queries) with no rate limit.
  - It scrapes search engines with a spoofed browser user agent.
- The "chunked TXT not joined" defect is in that project's Python ownership verifier. GuardHub's
  Go verifier uses the standard resolver, which joins the strings of one record. A regression test
  proves it.

## Decision

1. **Re-implement in Go from the specification.** The source engines are a checklist of ideas and
   test fixtures, not code to port. No Rust runtime or sidecar is added (§4): the TLS work fits in
   Go with hand-built ClientHellos and `crypto/tls`, inside the existing probe client's guard,
   budget, rate limit and timeouts.
2. **Every deepened analysis is a new check id and module** (`tls_config`, then `http_hardening`,
   `dns_email`, `subdomain_takeover`). The live checks keep their findings, so nothing goes live
   unmeasured, and the new modules ship disabled (§12.4).
3. **A validation lab measures every check** (`test_corpus/`, `scanner lab`):
   - Targets: real vulnerable apps and products pinned by digest, a known-clean reference, and
     synthetic targets that are each wrong in exactly one way.
   - Ground truth: hand-written manifests with a reason for every entry, verified with independent
     tools (curl, openssl, a full `crypto/tls` handshake), never with scanner output.
   - Safety: the lab network has no internet, and the runner can only scan `*.lab.test` hosts on
     its allowlist.
4. **Enabling a check module requires a measured accuracy** of precision >= 95%, recall >= 80%
   (within the check's declared scope), at least 3 ground-truth findings, a clean target and no
   check errors. It is enforced by the API (`module_not_measured`, fails closed) from
   `packages/shared/accuracy.json`. CI regenerates that file and fails if it is stale.
5. **Severities follow real risk, not alarm.** Examples: 3DES is low; missing TLS 1.3 is info.
   Missing OCSP stapling and TLS_FALLBACK_SCSV are not reported, because the advice would be
   outdated or impossible to measure.

## Consequences

- The four engines are Go code GuardHub owns, with tests and measured accuracy, but more work
  than a port.
- The lab already paid for itself on the existing checks:
  - It found 4 real false-positive or recall bugs in live checks: non-HTML responses judged as
    pages, the WordPress installer reported as a login (2 paths), and Grafana's SPA login missed.
  - It found 2 mistakes in the ground truth (Grafana's open `/metrics`; Apache's 404 footer
    follows `ServerTokens`).
  - All were fixed with regression tests.
- Recall is reported twice: within the declared scope (the gate) and against all ground truth
  ("Recall (all)"), so catalogue-based checks cannot hide what they do not cover.
- Some samples are small (3 to 4 positives for several checks). The scorecards say so, and the lab
  grows with every check.
