# Check `header_quality` — what the browser-policy headers actually allow

- **Code:** `apps/scanner/internal/checks/header_quality.go` (CSP parsing shared with `http_hardening`, `csp.go`) · tests: `header_quality_test.go`
- **i18n:** `checks.json` → `header_quality` (en, tr; the other locales are queued, §7.5)
- **Module:** ships disabled (migration 0009)
- **Accuracy:** [`docs/accuracy/header_quality.md`](../accuracy/header_quality.md) · **Decision record:** [ADR-0007](../adr/0007-phase4a-depth-methodology.md)

## What it detects

Passive: it only reads the cached GET of the home page.

| Finding key | Severity | When |
|---|---|---|
| `csp_unsafe_eval` | low | every enforced policy with a script directive allows `'unsafe-eval'` in it (`script-src`, else `default-src`) |
| `csp_base_uri_missing` | low | a policy uses script nonces (or hashes with `'strict-dynamic'`), and no policy sets `base-uri` |
| `csp_object_src_unrestricted` | info | no policy restricts `object-src`. It counts as unrestricted when absent, or when only a `default-src` with a broad source (`*`, `http:`, `https:`, `ftp:`, `http(s)://*`) applies |
| `permissions_policy_missing` | info | an HTML page without `Permissions-Policy` |
| `coop_missing` | info | an HTML page without `Cross-Origin-Opener-Policy` |
| `cookie_response_cacheable` | medium | the response sets a cookie and its `Cache-Control` explicitly allows shared caching: `public`, a positive `s-maxage`/`max-age`, and no `private`/`no-store`/`no-cache` |

**CSP sources:** the header, plus `<meta http-equiv>` in the first 64 KiB of the page.
Report-Only policies are ignored, because browsers do not enforce them.

**Severity (ADR-0007 rubric):**

- **low** for `unsafe-eval` and a missing `base-uri`: each needs an injection bug first.
- **info** for `object-src`, Permissions-Policy and COOP: browsers no longer run plugins, and
  the other two are best practice.
- **medium** for a cacheable cookie response. One visitor's cookie served to others is a session
  leak, but it needs a shared cache configured to store it.

## Not reported here (other checks own it)

| Finding | Reported by |
|---|---|
| No CSP at all | `security_headers` (`csp_missing`) |
| `'unsafe-inline'` without nonce/hash, wildcard script sources | `http_hardening` (`csp_ineffective`) |
| Framing protection | `security_headers` (`clickjacking_unprotected`), `http_hardening` (`xfo_ineffective`) |
| Referrer policy | `http_hardening` |
| nosniff | `security_headers` |
| Cookie flags | `security_headers` (`cookie_flags_missing`) |

## Deliberate limits

- **Non-HTML answers:** an API answer, an empty 404 or a redirect to another host get no
  document findings.
- **No Cache-Control:** a response without `Cache-Control` is not reported as cacheable. CDNs do
  not cache `Set-Cookie` responses by default.
- **`'unsafe-eval'` in `style-src`:** Observatory also flags it there. This check does not,
  because it has no effect.

## Ground truth (validation lab)

**Independent tools, run inside the lab against every site target**
(`test_corpus/oracles/headers/`, versions locked in its `package-lock.json`):

| Key | Truth source |
|---|---|
| `csp_unsafe_eval`, `csp_object_src_unrestricted` | Mozilla's HTTP Observatory scanner `@mdn/mdn-http-observatory` 1.4.8 (`policy.unsafeEval`, `policy.unsafeObjects`) |
| `csp_base_uri_missing` | Google's CSP Evaluator `csp_evaluator` 1.1.8 (`checkMultipleMissingBaseUriDirective`) |
| `permissions_policy_missing`, `coop_missing`, `cookie_response_cacheable` | the headers fetched by the oracle (RFC 9111 directives) |

**Lab targets** (`hq-*`, `nginx/hq.conf`): each is `clean.lab.test` with one difference.

| Kind | Targets |
|---|---|
| Positives | `hq-eval`, `hq-nonce`, `hq-object`, `hq-noperm` (two keys), `hq-cache` |
| Look-alike negatives | `hq-wasm` (`'wasm-unsafe-eval'`), `hq-private` (`private, max-age`) |

The hardened references (`clean`, `tls-*`, `td-*`, `hh-*`, DNS web) send Permissions-Policy and
COOP. The third-party apps (Juice Shop, DVWA, WordPress, …) are scored as they ship.

**Measured 2026-11-22** on the 47 site targets served by `clean`, `hq`, `hh`, `td` and
`dns-web`: 6 TP, 0 FP, 0 FN, 0 errors (scorecard in `docs/accuracy/header_quality.md`). The
oracle agreed with the lab design on every target. `td-sha1` (SHA-1 certificate, refused by
Node) was read with certificate checks relaxed: no keys. CI's `header-truth` job
(`test_corpus/oracles/headers/run.sh`) re-runs the oracle on every site target on each push,
the third-party apps one at a time, and fails when a manifest disagrees with it or a target
cannot be read (`compare.py`).
