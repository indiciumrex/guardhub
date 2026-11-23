# `js_libraries` accuracy

Lab source revision `2f16aaca7c6a`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 71.4% | 5 | 0 | 0 | 2 | 0 | 104 | 98 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `vulnerable_js_library` | 5 | 0 | 2 |

## False positives (0)

None.

## False negatives (2)

- `grafana` / `vulnerable_js_library` at `http://grafana.lab.test:3000/public/build/4315.04038860e30ccfb6f1fb.js` (outside the declared scope): JS oracle (retire.js 6.1.1, repository pinned at RetireJS commit 0a99704, local lab run 2026-11-23): the bundle (909850 bytes) contains DOMPurify 3.2.4 (22 vulnerabilities) and lodash 4.17.21 (2 vulnerabilities: CVE-2025-13465, CVE-2026-4800). OSV (recorded 2026-11-23, test_corpus/osv): npm dompurify@3.2.4 has 22 advisories.
- `grafana` / `vulnerable_js_library` at `http://grafana.lab.test:3000/public/build/6029.0549a3fcb50e73c4b256.js` (outside the declared scope): JS oracle (retire.js 6.1.1, repository pinned at RetireJS commit 0a99704, local lab run 2026-11-23): the bundle (409895 bytes) contains moment.js 2.30.1, 1 vulnerability (CVE-2026-17495). OSV (recorded 2026-11-23, test_corpus/osv): npm moment@2.30.1 has 1 advisory.

## True positives (5)

- `js-bootstrap` / `vulnerable_js_library` at `https://js-bootstrap.lab.test/static/bootstrap.min.js`: JS oracle (retire.js 6.1.1, repository pinned at RetireJS commit 0a99704, local lab run 2026-11-23): /static/bootstrap.min.js is bootstrap 3.3.7 by its content, 8 vulnerabilities incl. CVE-2018-14040, CVE-2018-14042, CVE-2019-8331. OSV (recorded 2026-11-23, test_corpus/osv): npm bootstrap@3.3.7 has 7 advisories.
- `js-cdn` / `vulnerable_js_library` at `https://code.jquery.com/ui/1.12.1/jquery-ui.min.js`: JS oracle (retire.js 6.1.1, repository pinned at RetireJS commit 0a99704, local lab run 2026-11-23): the script URL is jquery-ui 1.12.1 (uri), 4 vulnerabilities: CVE-2021-41182, CVE-2021-41183, CVE-2021-41184, CVE-2022-31160. OSV (recorded 2026-11-23, test_corpus/osv): npm jquery-ui@1.12.1 has 4 advisories.
- `js-jquery` / `vulnerable_js_library` at `https://js-jquery.lab.test/static/jquery.min.js`: JS oracle (retire.js 6.1.1, repository pinned at RetireJS commit 0a99704, local lab run 2026-11-23): /static/jquery.min.js is jquery 1.12.4 by its content (filecontent), 6 vulnerabilities incl. CVE-2015-9251, CVE-2019-11358, CVE-2020-11022, CVE-2020-11023. OSV (recorded 2026-11-23, test_corpus/osv): npm jquery@1.12.4 has 4 advisories.
- `js-moment` / `vulnerable_js_library` at `https://js-moment.lab.test/static/moment.js`: JS oracle (retire.js 6.1.1, repository pinned at RetireJS commit 0a99704, local lab run 2026-11-23): /static/moment.js is moment.js 2.18.1 by its content, 3 vulnerabilities: CVE-2017-18214, CVE-2022-24785, CVE-2022-31129. OSV (recorded 2026-11-23, test_corpus/osv): npm moment@2.18.1 has 3 advisories.
- `juice-shop` / `vulnerable_js_library` at `http://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`: JS oracle (retire.js 6.1.1, repository pinned at RetireJS commit 0a99704, local lab run 2026-11-23): the home page loads //cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js, jquery 2.2.4 by its URL, 6 vulnerabilities incl. CVE-2015-9251, CVE-2019-11358, CVE-2020-11022, CVE-2020-11023. OSV (recorded 2026-11-23, test_corpus/osv): npm jquery@2.2.4 has 4 advisories.

