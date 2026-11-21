# Check `tls_config` — TLS configuration

- **Code:** `apps/scanner/internal/checks/tls_config.go`, `tlshello.go` (+ `internal/probe/rawtls.go`) · tests: `tls_config_test.go`, `probe/rawtls_test.go`
- **Category:** transport · **i18n:** `checks.json` → `tls_config` · **Module:** ships disabled (migration 0005); enabling requires the accuracy gate
- **Accuracy:** [`docs/accuracy/tls_config.md`](../accuracy/tls_config.md)
- **Decision record:** [ADR-0004](../adr/0004-phase2-reimplementation-and-accuracy-gate.md)

How HTTPS is configured beyond the certificate basics of `tls_cert`.

## What it detects

| Finding key | Severity | Params | Trigger |
|---|---|---|---|
| `weak_cipher_insecure` | high | `suite` | the server accepts a NULL, anonymous, export, single-DES or RC4 suite |
| `weak_cipher_3des` | low | `suite` | the server accepts a 3DES suite (Sweet32: practical only with huge traffic) |
| `no_forward_secrecy` | medium | `suite` | no TLS 1.3, (EC)DHE suites refused, static-RSA key exchange accepted |
| `chain_incomplete` | medium | `issuer` | the chain does not verify, the leaf is not self-signed, its issuer is not served, and the leaf names its issuer's AIA URL |
| `cert_weak_key` | medium | `key_type`, `bits` | leaf key below RSA 2048 / EC 256 bits |
| `tls13_unsupported` | info | – | the best version negotiated (offering 1.0–1.3) is below TLS 1.3 |

Severities follow real risk. Only suites that let an on-path attacker read or change traffic are
high. 3DES is low and missing TLS 1.3 is info (best practice, not a vulnerability).

**Deliberately not reported:**
- **Missing OCSP stapling.** Let's Encrypt ended its OCSP service in 2025, and the CA/Browser
  Forum made OCSP optional, so the advice would be wrong.
- **Missing TLS_FALLBACK_SCSV.** TLS 1.3 has built-in downgrade protection. Every mainstream TLS
  stack has honoured SCSV since 2015, so it cannot be measured. Legacy protocols, the real
  downgrade risk, are `tls_cert`'s `legacy_tls_supported`.
- **SSLv2/SSLv3.** Current TLS libraries cannot even build them.

## Requests sent

All requests are TLS handshakes; there are no HTTP requests and no application data.

1. **One normal handshake** (`crypto/tls`, TLS 1.0–1.3 offered). It gives the negotiated version,
   the leaf key and the served chain. If it fails, the check reports **nothing**: no HTTPS is
   `tls_cert`'s `https_unavailable`. For an `https://` target whose TCP connection fails, the
   check returns a `target_unreachable` error.
2. **Two raw ClientHellos** (TLS 1.2), one offering only the insecure suites and one only the 3DES
   suites. Each reads only the server's first answer (ServerHello or alert), then closes the
   connection.
3. **Only when TLS 1.3 is unavailable:** one raw ClientHello offering only (EC)DHE suites. If that
   is refused, one more offering only static-RSA suites.

That is **3 to 5 connections**, all through the probe client: IP guard, per-host rate limit,
request budget, timeouts.

## How it verifies

- The raw ClientHello looks like a normal client (SNI unless the host is an IP, supported_groups,
  ec_point_formats, signature_algorithms, renegotiation SCSV), so the answer reflects the server's
  configuration.
- **A suite counts as accepted only when the ServerHello picks a suite we offered.** A server
  answering with anything else proves nothing. This test exists because the Rust engine this
  check replaces recorded "Export accepted" for any server that supported AES-128.
- The ServerHello parser handles records that are split or merged, alerts, a closed connection
  (a refusal) and non-TLS answers. A probe that times out is **skipped, never guessed**.
- `chain_incomplete` uses the AIA rule to tell "intermediate not served" (fix: serve
  `fullchain.pem`) apart from "private CA" (`tls_cert`'s `cert_untrusted`).

## Evidence

Kind `tls_handshake`, location `host:port`. The payload names the offered category and the suite
the server accepted, or the key type and size, or the missing issuer and its AIA URL. All of it is
public handshake data; nothing secret is captured.

## False-positive risks

- **A TLS-terminating proxy or CDN in front of the site.** The finding describes the edge the
  visitor talks to, which is the right thing to report. The fix belongs in the CDN or proxy
  settings, and the texts say so.
- **Middleboxes that answer every hello.** Covered: only a ServerHello choosing an offered suite
  counts.

The [lab scorecard](../accuracy/tls_config.md) lists measured precision and recall per finding
key.
