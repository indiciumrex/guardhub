# ADR-0007 — Phase 4A: depth methodology (new gated modules, severity rubric, independent truth)

- **Status:** accepted
- **Date:** 2026-11-22
- **Context owner:** Phase 4A ("Dünya standardında derinlik")
- **Touches:** GUARDHUB_STANDARDS §2 (accuracy before volume), §7.5 (i18n), §8.3 (module flags), §9.2

## Context

Phase 4A asks for deeper passive analysis than the free tools give (SSL Labs, securityheaders,
Observatory, MXToolbox) in seven areas:

- TLS and certificates
- header quality
- DNS and e-mail
- technology fingerprint with known CVEs
- misconfiguration
- cookies
- content signals

Each must have a severity rule, en/tr texts, fix steps, masked evidence and a measured accuracy
scorecard (≥95% precision, ≥80% recall) against an independent source of truth.

Most of the existing checks are already **enabled in production** (`tls_cert`, `tls_config`,
`security_headers`, `http_hardening`, `dns_email`, `exposed_env`, `open_admin`, `info_leak`,
`default_creds`, `subdomain_takeover`).

## Decision

### 1. Depth ships as new modules, never as new keys of an enabled module

A new finding key added to an enabled check would go live with the next deploy, with no flag of
its own and before its accuracy is measured. Every Phase 4A area is therefore a **new check id
with its own module row, shipped disabled**. It is switched on in the admin only after the
gate passes.

Existing checks keep their keys and behaviour. The new ones never repeat a finding an existing
check already reports; each check's doc lists the overlap it avoids (for example,
`tls_depth` leaves a short HSTS max-age to `hsts_weak`).

| Area (prompt) | Module | Independent truth |
|---|---|---|
| TLS / certificate depth | `tls_depth` | testssl.sh 3.2 |
| Header quality | `header_quality` | Mozilla HTTP Observatory scanner 1.4.8 and Google CSP Evaluator 1.1.8, run unmodified in the lab (`test_corpus/oracles/headers`) |
| DNS & e-mail depth | e-mail transport / DNS hardening module (MTA-STS, TLS-RPT, DKIM, DNSSEC, CAA, DANE) | dig, plus independent parsers |
| Technology + known CVEs | fingerprint module (CVE only when the version is certain) | curated version fixtures, plus OSV and retire.js |
| Misconfiguration | exposed-files module (`.DS_Store`, backups, source maps, default pages) | curated fixtures, plus the request log |
| Cookies | cookie module (SameSite, scope, prefixes) | Observatory cookie rules re-implemented independently |
| Content signals | content module (mixed content, SRI, keys in JS bundles) | curated fixtures, plus gitleaks rules |

Module names are fixed in each check's doc when the check lands.

### 2. Severity rubric (CVSS-like, applied to every new key)

| Severity | Rule |
|---|---|
| critical | proven exposure an outsider can use right now (a working secret, readable data) |
| high | a weakness an outsider can exploit directly, with no help from the victim |
| medium | needs extra conditions (an attacker on the network, a victim's click), or makes major browsers refuse the site |
| low | defence in depth is missing, or only some clients are affected |
| info | best practice; no direct risk |

- **The rating is the exposure GuardHub can prove from outside**, not the worst case of the
  underlying issue. Nothing is "high" because a related CVE score is high.
- **Each check's doc gives the reason for each key's level.**

### 3. Lab and truth

- **Every new key has at least one positive lab target and at least one negative look-alike.**
- **Expectations cite the independent tool's output on that target**, never GuardHub's own.
- **New targets are hardened clones of `clean.lab.test` that differ in exactly one property**,
  so the rest of the scanner must stay silent on them. That measures the other checks' false
  positives too.

### 4. Languages

**en + tr only.** The founder decided (2026-11-22) to follow §7.5: new texts are complete in
en and tr, and the other seven locales stay in the translation queue (falling back to en).
This phase does not claim nine-language coverage.

## Consequences

- **More modules in the admin list.** Each one is independently reversible.
- **Overlap rules make findings additive:** enabling a depth module never doubles an existing
  finding.
- **CI's accuracy job re-measures every module on every push.** A module that drops below the
  gate cannot be switched on (packages/shared/accuracy.json).
