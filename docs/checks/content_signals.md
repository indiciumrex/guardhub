# Check `content_signals` — what the home page makes a browser load

- **Code:** `apps/scanner/internal/checks/content_signals.go` · tests: `content_signals_test.go`
- **i18n:** `checks.json` → `content_signals` (en, tr; the other locales are in the translation queue, §7.5)
- **Module:** ships disabled (migration 0014)
- **Accuracy:** [`docs/accuracy/content_signals.md`](../accuracy/content_signals.md) · **Decision record:** [ADR-0007](../adr/0007-phase4a-depth-methodology.md) ("content signals")

## What it detects

| Finding key | Severity | Params | When |
|---|---|---|---|
| `mixed_content_active` | medium | `count`, `example` | an HTTPS home page loads a script (`<script src>`), stylesheet (`<link rel=stylesheet>`) or frame (`<iframe>`) from an `http://` URL |
| `mixed_content_passive` | low | `count`, `example` | an HTTPS home page loads an image (`<img src>`), audio or video (`src`, or `<source src>` inside them) from an `http://` URL |
| `sri_missing` | info | `count`, `example` | a script from **another site** (another registrable domain, eTLD+1) loads over https without an `integrity` attribute |

One finding per key and page. The evidence lists up to 5 URLs.

**Severity (ADR-0007 rubric):**

- **medium (`mixed_content_active`):** browsers block active mixed content, so the page breaks.
  Where it loads, an attacker on the network can replace it.
- **low (`mixed_content_passive`):** current browsers upgrade the request or warn. Only older
  clients load it in clear.
- **info (`sri_missing`):** a best practice. It applies only to files that never change, and
  analytics or chat scripts cannot use it.

## How it works

- **Reading:** the home page (after same-host redirects) is read as HTML with the
  `golang.org/x/net/html` tokenizer. Relative URLs resolve against the page, or its first
  `<base href>`.
- **Never counted:**
  - comments;
  - `<noscript>` contents (browsers run scripts, so they ignore it);
  - `<template>` contents (inert);
  - links (`<a href>`), `<link rel=alternate|preload|icon>`, and text inside scripts.
- **Not mixed content:** `http://localhost` and loopback addresses. Browsers treat them as
  potentially trustworthy (W3C Secure Contexts).
- **Requests:** the home page only. Nothing it references is fetched.

## Not covered (declared scope)

- `srcset`, CSS `url()` and `@import` inside stylesheets, scripts that a script adds, `<object>` and
  `<embed>`, form actions.
- Anything after the home page, and anything past the probe's 256 KiB read.
- An HTTP page has no mixed content. Its own insecurity is `tls_cert`'s finding.

## Validation

**Lab targets** (`cs-*`, `nginx/cs.conf`, pages in `test_corpus/cs/`): `clean`'s headers and TLS.
The CSP allows exactly the test hosts, so the browser gets as far as its mixed-content decision.

- **Positives:**
  - an http:// script (`cs-script`);
  - an http:// stylesheet (`cs-style`);
  - an http:// image (`cs-img`);
  - a cross-site https script without integrity (`cs-sri`).
- **Negatives:**
  - the same script with integrity (`cs-sriok`);
  - http:// URLs only in a comment, `<noscript>`, `<template>`, a link and script text (`cs-markup`);
  - `clean` and every other lab target.

**Independent truth** (CI's `header-truth` job, via `oracles/headers/run.sh`):

- **Mixed content:** `test_corpus/oracles/content/oracle_content.mjs`.
  - Chromium (Playwright 1.65.1, Microsoft's image pinned by digest) loads each home page.
  - The DevTools Audits domain reports the browser's own `MixedContentIssue` decisions:
    `MixedContentBlocked` → active; automatically upgraded or warned → passive.
- **SRI:** Mozilla HTTP Observatory 1.4.8's `subresource-integrity` test (`oracle_headers.mjs`).
  A script it counts as foreign, without integrity, that loads over https, is `sri_missing`.

`compare.py` fails the job on any manifest mismatch.
