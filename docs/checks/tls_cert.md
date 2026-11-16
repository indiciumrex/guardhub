# Check `tls_cert` — HTTPS and certificate

- **Code:** `apps/scanner/internal/checks/tls.go` (+ `internal/probe/tls.go`) · tests: `tls_test.go`
- **Category:** transport · **i18n:** `checks.json` → `tls_cert`

## What it detects

| Finding key | Severity | Params | Trigger |
|---|---|---|---|
| `https_unavailable` | high | – | no TLS handshake possible on the https port (for an `http://` target: port 443 of the same host) |
| `http_not_redirected` | medium | – | `http://host/` answers but does not 3xx-redirect to an `https://` URL |
| `cert_expired` | critical | `expired_on` (YYYY-MM-DD) | leaf `NotAfter` < now |
| `cert_expiring_soon` | medium | `days_left`, `expires_on` | expires within 30 days |
| `cert_hostname_mismatch` | high | `host` | the leaf is not valid for the hostname |
| `cert_untrusted` | high | – | the chain does not verify against the system roots (self-signed, missing intermediate, unknown CA) |
| `legacy_tls_supported` | medium | `version` (e.g. `TLS 1.0`) | the server completes a handshake with TLS 1.0 or 1.1 |

## Requests sent

1. **TLS handshake only** (no HTTP request) to `host:443`, or to the target's own port for `https://host:port` targets. It offers TLS 1.0–1.3 so that legacy-only servers can still be inspected.
2. If step 1 negotiated TLS 1.2 or higher: one more **handshake only**, capped at TLS 1.1. If it succeeds, the server supports a legacy protocol.
3. `GET http://host/` **without following redirects** (port 80, or the target's port for `http://host:port` targets).

That is at most 2 handshakes and 1 GET. Step 3 is skipped when HTTPS is unavailable, because the redirect finding would be redundant.

## How it verifies

- Certificates come from the handshake. Verification is done in the check with an **injectable clock** (`TLSCert.Now`) and roots (`TLSCert.Roots`; nil means system roots), so tests are deterministic.
- Each problem is reported once. Expiry is checked first. The hostname is checked with `VerifyHostname`. Trust is checked with `x509.Verify` at a moment inside the leaf's validity window (so an expired certificate is not also reported as untrusted), with the server-sent intermediates and `ServerAuth` usage.
- `days_left` is the whole number of days until `NotAfter`.
- A redirect to any https URL (including `www.`) passes the redirect test.
- If the target is `https://` and the TCP connection itself fails, the check reports a `target_unreachable` error instead of a finding.

## Evidence

Kind `tls_handshake` with location `host:port`, and a payload with the protocol, subject, issuer, names and validity dates (certificates are public data). `http_not_redirected` uses kind `http_response` with location `http://host/`, and its payload shows the status and `Location` header.

## Plain-language text (en)

For example, `cert_expired`: "Certificate expired on {expired_on}". Browsers now show a full-page warning, and most visitors leave. Fix: renew (Let's Encrypt/certbot, or the hosting provider's automatic TLS), install the full chain, turn on auto-renewal, re-scan. See the catalog for every key.

## False-positive risk: low

- Hostname mismatch and trust are decided by the same algorithms browsers use.
- Sites that intentionally serve only HTTP (rare today) still get `https_unavailable`; that is the intended advice.
- Some CDNs keep TLS 1.0/1.1 on for very old clients; the finding is correct, and the fix explains how to disable them.

## Why it is do-no-harm

Two bare TLS handshakes that are closed immediately, plus one GET. No application data is sent over TLS, and the weak cipher suites offered in the legacy probe carry no data.
