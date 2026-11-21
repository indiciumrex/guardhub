# Check `http_hardening` — browser policies (CORS, CSP quality, framing, referrer)

- **Code:** `apps/scanner/internal/checks/http_hardening.go`, `csp.go` · tests: `http_hardening_test.go`
- **Category:** hardening · **i18n:** `checks.json` → `http_hardening` · **Module:** ships disabled (migration 0005); enabling requires the accuracy gate
- **Accuracy:** [`docs/accuracy/http_hardening.md`](../accuracy/http_hardening.md) · **Decision record:** [ADR-0004](../adr/0004-phase2-reimplementation-and-accuracy-gate.md)

Whether the policies that tell browsers how to treat the site actually protect it.
`security_headers` reports policies that are **missing**; this check reports policies that are
**present but ineffective**, plus CORS. Each problem is reported by one check only.

## What it detects

| Finding key | Severity | Params | Trigger |
|---|---|---|---|
| `cors_any_origin_with_credentials` | high | `origin` | `Origin: https://guardhub-cors-check.invalid` is echoed in `Access-Control-Allow-Origin` **and** `Access-Control-Allow-Credentials: true` |
| `cors_null_origin_with_credentials` | medium | – | `Origin: null` gets `Access-Control-Allow-Origin: null` + credentials (only checked when the previous one is not found) |
| `csp_ineffective` | low | `reasons` (CSP syntax, e.g. `script-src 'unsafe-inline'`) | every enforced policy (header or `<meta>`) lets injected scripts run |
| `xfo_ineffective` | low | `value` | `X-Frame-Options` is present but not `DENY`/`SAMEORIGIN` (e.g. `ALLOW-FROM`), and no header CSP sets `frame-ancestors` |
| `referrer_policy_unsafe_url` | low | – | the last recognised `Referrer-Policy` token is `unsafe-url` |

**Severities:**
- **CORS with credentials is high:** any website can read logged-in responses.
- **`csp_ineffective` is low:** without a CSP at all (`security_headers`' `csp_missing`, medium) the
  page has no script protection; a weak CSP still provides other protections such as
  frame-ancestors.

## How it decides (CSP Level 3 semantics)

- **Scripts follow `script-src`, else `default-src`.** With neither, scripts are unrestricted.
- **A nonce or hash neutralises `'unsafe-inline'`** (browsers ignore it then), and
  **`'strict-dynamic'` neutralises host and scheme sources** (`https:`, `*`). The backwards-
  compatible strict policy Google recommends is therefore *not* reported. The engine this check
  replaces flagged it, because it substring-matched the whole policy.
- **Only `*`, `http:`, `https:` and `data:` count as "anywhere".** `*.cdn.example.com` is a host
  source, and `report-uri http://…` is not a script source.
- **Several enforced policies (several headers, or a header plus `<meta>`) all apply.** Scripts are
  stopped if any one of them stops them, so the check reports only when all are weak.
  Report-Only policies are not enforced and are ignored.
- **Not reported:**
  - `'unsafe-eval'` alone: common in frameworks, and it needs a separate injection sink.
  - A missing `object-src`: browsers no longer run plugins.
- **CORS:**
  - `*` never counts, because browsers refuse credentials with a wildcard; public APIs legitimately
    use it.
  - Reflection without credentials exposes only public data, so it is not reported.
  - Only the home page is tested (declared scope).
- **Document checks only apply to HTML documents** (not redirects to another host, empty 404s or
  JSON).

## Requests sent

1. The cached `GET /` (shared with the other checks).
2. `GET /` with `Origin: https://guardhub-cors-check.invalid`. `.invalid` is a reserved TLD that
   never resolves.
3. Only if 2 found nothing: `GET /` with `Origin: null`.

At most 3 GETs, uncached for the two Origin variants. **No cookies are sent, nothing is submitted,
and no method other than GET is used.**

## Deliberately not checked

- **"Allowed HTTP methods".** Proving that PUT, DELETE or TRACE works means sending them, which
  §9.2 forbids. An `Allow`/OPTIONS answer alone is unreliable: frameworks advertise generically,
  and single-page apps answer 200 to everything. The engine this replaces actually sent PUT,
  DELETE, TRACE, a `DEBUG stop-debug` and a POST to `/forgot-password`.
- **Host-header and cache-poisoning probes.** They can poison a shared cache: not passive.

## Evidence

Kind `http_header`, location = the URL. The payload is the relevant response headers (and, for
CORS, the Origin we sent). Cookie values are never included.

## False-positive risks

- **CORS that is deliberately open for a public, unauthenticated API but still sends credentials.**
  That is still dangerous whenever the same host also uses cookies, so it is reported.
- **A CSP enforced by a CDN on some paths only.** The check reads the home page.
