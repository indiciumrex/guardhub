# Check `js_libraries` — JavaScript libraries with known vulnerabilities

- **Code:** `apps/scanner/internal/checks/js_libraries.go` · tests: `js_libraries_test.go`
- **i18n:** `checks.json` → `js_libraries` (en, tr; the other locales are in the translation queue, §7.5)
- **Module:** ships disabled (migration 0013)
- **Accuracy:** [`docs/accuracy/js_libraries.md`](../accuracy/js_libraries.md) · **Decision record:** [ADR-0007](../adr/0007-phase4a-depth-methodology.md) ("technology + known CVEs")

## What it detects

| Finding key | Severity | Params | When |
|---|---|---|---|
| `vulnerable_js_library` | medium | `library`, `version`, `advisories`, `fixed_version`, `script` | the home page loads a catalogued library at a **certain** version, and OSV lists at least one advisory (not withdrawn) for that exact npm version |

One finding per (library, version), at the first script that shows it.

**Severity (ADR-0007 rubric):** medium.

- Client-side library flaws (mostly cross-site scripting, prototype pollution) need extra
  conditions: the page must pass attacker-controlled input to the affected function, and a
  victim must load it.
- GuardHub cannot see that from outside. So it is never high, however the advisory itself is
  scored: "nothing is high because a related CVE score is high".

## When a version counts as certain

- **Same-origin scripts:** the file is fetched and the version is read from the **library's own
  banner comment**, as its distribution files ship it (for example `/*! jQuery v1.12.4 |`,
  `* Bootstrap v3.3.7 (http://getbootstrap.com)`, `//! moment.js` + `//! version : 2.18.1`).
  - **File names are never trusted:** `/static/jquery-1.8.3.min.js` that contains jQuery 3.7.1 is
    jQuery 3.7.1.
  - **A mention elsewhere is not a banner:** for example "needs jQuery v1.12.4" in a comment.
- **Cross-origin scripts are never fetched.** Their version is read from the path of a
  well-known CDN that serves exactly one version per URL:
  - code.jquery.com;
  - cdnjs.cloudflare.com (`/ajax/libs/<name>/<version>/`);
  - cdn.jsdelivr.net (`/npm/<pkg>@<version>/`) and unpkg.com (`/<pkg>@<version>/`), exact
    versions only (`jquery@3` is a range and is skipped);
  - ajax.googleapis.com;
  - BootstrapCDN.

**Catalogue:**

| npm package | Banner / CDN names |
|---|---|
| `jquery` | `jQuery v…`, `jQuery JavaScript Library v…` |
| `jquery-ui` | `jQuery UI - v…` (the full build) |
| `jquery-migrate` | `jQuery Migrate v…` |
| `bootstrap` | `Bootstrap v… (getbootstrap.com)` (cdnjs: `twitter-bootstrap`, `bootstrap`) |
| `angular` | `@license AngularJS v…` (AngularJS 1.x) |
| `moment` | `//! moment.js` / `//! version : …` |
| `handlebars` | `@license handlebars v…` |
| `dompurify` | `/*! @license DOMPurify …` |
| `vue` | `* Vue.js v…` (Vue 2) |
| `knockout` | `Knockout JavaScript library v…` |

Anything else (for example lodash, whose banner names no version, or Underscore, which lodash
credits in its own banner) is out of scope.

## Limits (declared scope)

- **Scripts:** the first 10 `<script src>` tags of the home page (after same-host redirects).
  - At most 6 same-origin scripts are fetched.
  - Each script is read up to the probe's 256 KiB cap. A banner further into a large bundle is
    not seen.
- **Server software versions are out of scope** (`Server`, `X-Powered-By`). Distributions
  backport security fixes without changing the version string, so the version does not decide
  the vulnerability. `info_leak` reports the disclosure itself.
- **Data sent to OSV (`api.osv.dev`, ADR-0006 §7):** only npm package names and versions,
  never the target.
  - The OSV requests do not count against the per-scan request budget for the target.
  - At most 100 advisory records are fetched per scan.
  - When OSV cannot be reached, the check reports an error. It never reports "no
    vulnerabilities".

## Validation

**Lab targets** (`js-*`, `nginx/js.conf`, `jslab/`): `clean`'s headers and TLS, plus the
libraries' **real distribution files from npm** at exact versions, baked into the image at build
time.

- **Positives:**
  - jQuery 1.12.4 (`js-jquery`);
  - Bootstrap 3.3.7 (`js-bootstrap`);
  - Moment 2.18.1 (`js-moment`);
  - jQuery UI 1.12.1 from code.jquery.com (`js-cdn`, never fetched).
- **Negatives:**
  - jQuery 3.7.1 (`js-current`);
  - jQuery 3.7.1 named `jquery-1.8.3.min.js` (`js-renamed`);
  - a comment mentioning jQuery v1.12.4 (`js-mention`).
- **Third-party apps:**
  - Juice Shop loads jQuery 2.2.4 from cdnjs: a positive.
  - Grafana's bundles hold vulnerable Moment, DOMPurify and lodash past the 256 KiB read and
    outside the catalogue. These are marked as outside the declared scope.

**Independent truth:** `test_corpus/oracles/js/oracle_js.mjs`, run by `oracles/headers/run.sh`
in CI's `header-truth` job on every site target.

- **retire.js 6.1.1**, its own matchers unmodified:
  - `scanFileContent` for same-origin scripts, judged by content only;
  - `scanUri` for cross-origin ones.
- **The vulnerability repository** is pinned to a RetireJS commit and checked by sha256.
- **The OSV answers the lab replays** (`test_corpus/osv`, `osv/site-queries.txt`) were recorded
  from api.osv.dev. They agree with retire.js on every lab library version.

`compare.py` fails the job on any manifest mismatch.
