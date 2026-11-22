# Check `tls_depth` — what browsers demand from a certificate beyond "valid"

- **Code:** `apps/scanner/internal/checks/tls_depth.go` · tests: `tls_depth_test.go`
- **i18n:** `checks.json` → `tls_depth` (en, tr; the other locales are in the translation queue, §7.5)
- **Module:** ships disabled (migration 0009)
- **Accuracy:** [`docs/accuracy/tls_depth.md`](../accuracy/tls_depth.md) · **Decision record:** [ADR-0007](../adr/0007-phase4a-depth-methodology.md)

## What it detects

| Finding key | Severity | Params | When |
|---|---|---|---|
| `cert_weak_signature` | medium | `algorithm`, `subject` | a served certificate other than a self-signed root is signed with SHA-1 or MD5 (one finding per chain) |
| `cert_lifetime_too_long` | low | `days` | a **trusted** leaf issued on or after 2020-09-01 is valid for more than 398 days |
| `cert_no_sct` | medium | none | a **trusted** leaf has no Signed Certificate Timestamp, neither embedded nor in the TLS extension |
| `ocsp_stapling_missing` | info | none | a **trusted** leaf names an OCSP responder, but no OCSP response is stapled |
| `hsts_preload_ineligible` | low | `reason` | HSTS contains `preload` with max-age ≥ 180 days, but max-age < 1 year (`max_age`), no `includeSubDomains` (`include_subdomains`) or both |

**"Trusted"** means the served chain verifies for the host against the system roots (the lab uses
its own root). Lifetime, CT and stapling only matter for publicly trusted certificates. An
untrusted chain is `tls_cert`'s `cert_untrusted`, so it is not reported a second time here.

**Severity (ADR-0007 rubric):**

- **medium** for SHA-1/MD5 and missing CT. Both make Chrome or Safari reject the site, so
  visitors are turned away: an availability and trust failure. They do not expose data on
  their own.
- **low** for the lifetime (only some browsers reject it) and for a preload request that cannot
  be honoured.
- **info** for stapling: a privacy and performance improvement, not a weakness.

## How it works

1. **One TLS handshake** through the probe client (IP guard, request budget). Go's client asks
   for a stapled OCSP response and for SCTs, as browsers do.
2. **The chain is verified** with the scan's clock. Weak signatures are read from every served
   certificate. A self-signed root is skipped: clients never check a root's own signature.
3. **One GET of the HTTPS root** for `Strict-Transport-Security`. The probe client's cache
   shares it with `security_headers`.

## Not reported (false-positive discipline)

- **CT logs are not contacted.** The check tests that an SCT is present, as testssl.sh does. It
  does not verify the log's signature.
- **No staple validation.** A stapled response is not parsed or checked. A revoked status in a
  staple would need a separate finding (not in scope).
- **No duplicate of `hsts_weak`.** A preload request with max-age under 180 days is already
  `security_headers`' `hsts_weak`.
- **Not checked for preloading:** HTTP-to-HTTPS redirect of the apex and the "base domain only"
  rule (would need extra requests on other hosts).
- **Certificates issued before 2020-09-01** may legally be longer-lived.

## Validation

**Lab targets** (`td-*`, `nginx/td.conf`): each is `clean.lab.test` with exactly one difference.
`td-ocsp` staples a valid response (negative). Every expectation cites testssl.sh 3.2 output on
that target, an independent tool:

| Target | testssl.sh field | Value |
|---|---|---|
| `td-sha1` | `cert_signatureAlgorithm` | ECDSA with SHA1 |
| `td-longlife` | `cert_extlifeSpan` | 825 > 398 days |
| `td-nosct` | `certificate_transparency` | `--` |
| `td-ocspmiss` | `OCSP_stapling` | not offered (with an OCSP URL) |
| `td-preload` | `HSTS_subdomains` | only for this domain (with `preload`) |

**Agreement:** testssl.sh and the check agree on all 19 TLS targets (clean, `tls-*`, `td-*`).
