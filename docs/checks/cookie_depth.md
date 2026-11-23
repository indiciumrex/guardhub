# Check `cookie_depth` — cookie scope beyond the Secure / HttpOnly / SameSite flags

- **Code:** `apps/scanner/internal/checks/cookie_depth.go` · tests: `cookie_depth_test.go`
- **i18n:** `checks.json` → `cookie_depth` (en, tr; the other locales are in the translation queue, §7.5)
- **Module:** ships disabled (migration 0011)
- **Accuracy:** [`docs/accuracy/cookie_depth.md`](../accuracy/cookie_depth.md) · **Decision record:** [ADR-0007](../adr/0007-phase4a-depth-methodology.md)

## What it detects

| Finding key | Severity | Params | When |
|---|---|---|---|
| `cookie_prefix_invalid` | low | `cookie_name`, `reason` | a cookie named `__Secure-…` without `Secure` (`secure_missing`), or `__Host-…` without `Secure` (`secure_missing`), with a `Domain` attribute (`domain_set`) or with a `Path` other than `/` (`path_not_root`). Browsers refuse such cookies (RFC 6265bis §4.1.3). |
| `cookie_domain_too_broad` | low | `cookie_name`, `domain` | a session cookie set with a `Domain` attribute the browser accepts (the host itself or a parent that is not a public suffix): it is then sent to every subdomain of that domain. |

**Session cookie:** the name contains `sess`, `sid`, `auth`, `token` or `login` (case-insensitive). Names
containing `csrf` or `xsrf`, and the framework CSRF cookies `security_headers` knows, are excluded.

**Severity (ADR-0007 rubric):**

- **`cookie_prefix_invalid` is low.** The cookie is dropped, so the protection the prefix promises is
  absent, and a session cookie may stop working. Nothing is exposed by it.
- **`cookie_domain_too_broad` is low.** Exploiting it needs control of one subdomain (a takeover, a
  third-party site, user content), which is an extra condition.

## How it works

It reads the `Set-Cookie` headers of the cached GET of the origin root (shared with
`security_headers`: no extra request). The name and the scoping attributes are read per RFC 6265bis
§5.6:

- attribute names are case-insensitive;
- the last `Domain`/`Path` wins;
- a leading dot of `Domain` is ignored.

A cookie whose prefix is invalid is reported once, and its scope is not judged, because it is never
stored. One finding is reported per cookie name.

## Not reported (false-positive discipline)

- **Missing `Secure`, `HttpOnly` or `SameSite`.** These stay with `security_headers` (`cookie_flags_missing`). A `__Secure-` cookie
  without `Secure` therefore appears in both checks, for different reasons: the missing flag, and the
  browser refusing the cookie.
- **Non-session cookies with a `Domain`** (analytics, preferences). Sharing them is usually intended.
- **A `Domain` the browser refuses** (another site, or a public suffix such as `co.uk`): the cookie is never stored. The same applies to a `Domain` on an IP-address host, which has no subdomains.
- **Lower-case prefixes** (`__host-`). These are matched case-sensitively, as tough-cookie 5 and RFC 6265bis
  §4.1.3 do; some browsers now also match them case-insensitively.
- **Cookies set on other pages or by JavaScript.** Only the origin root's response is read.

## Validation

**Lab targets** (`ck-*`, `nginx/ck.conf`): each is `clean.lab.test` with a different `Set-Cookie`
header. The positives are:

- `ck-hostpath`: `__Host-` with `Path=/app`;
- `ck-hostdomain`: `__Host-` with `Domain`;
- `ck-secure`: `__Secure-` without `Secure`;
- `ck-domain`: session cookie with `Domain=lab.test`;
- `ck-domainself`: session cookie with `Domain` = the host itself.

The negatives are `ck-analytics` (a non-session cookie with `Domain`), `ck-foreign` (a `Domain` the
browser refuses) and `clean` (a correct `__Host-` cookie).

**Independent truth:**

- The header oracle (`test_corpus/oracles/headers`) passes every target's `Set-Cookie` headers to
  tough-cookie 5.1.2, the RFC 6265bis cookie jar that Mozilla's HTTP Observatory uses, with
  `prefixSecurity: "strict"`.
- A cookie the jar refuses for its prefix is `cookie_prefix_invalid`.
- A session-named cookie the jar stores as not host-only is `cookie_domain_too_broad`.
- CI's `header-truth` job runs this on every site target, starting the third-party apps one at a
  time, and fails on any manifest mismatch.
