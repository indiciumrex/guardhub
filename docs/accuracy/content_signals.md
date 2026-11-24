# `content_signals` accuracy

Lab source revision `8c94317d417a`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 5 | 0 | 0 | 0 | 0 | 115 | 110 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `mixed_content_active` | 2 | 0 | 0 |
| `mixed_content_passive` | 1 | 0 | 0 |
| `sri_missing` | 2 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (5)

- `cs-img` / `mixed_content_passive` at `https://cs-img.lab.test/`: Chromium (Playwright 1.65.1 image, DevTools Audits MixedContentIssue, local lab run 2026-11-23): MixedContentAutomaticallyUpgraded, Image http://cs-assets.lab.test/logo.png.
- `cs-script` / `mixed_content_active` at `https://cs-script.lab.test/`: Chromium (Playwright 1.65.1 image, DevTools Audits MixedContentIssue, local lab run 2026-11-23): MixedContentBlocked, Script http://cs-assets.lab.test/app.js.
- `cs-sri` / `sri_missing` at `https://cs-sri.lab.test/`: Mozilla HTTP Observatory 1.4.8 subresource-integrity test (local lab run 2026-11-23): sri-not-implemented-but-external-scripts-loaded-securely; https://cdn.example.test/lib.js without integrity.
- `cs-style` / `mixed_content_active` at `https://cs-style.lab.test/`: Chromium (Playwright 1.65.1 image, DevTools Audits MixedContentIssue, local lab run 2026-11-23): MixedContentBlocked, Stylesheet http://cs-assets.lab.test/site.css.
- `js-cdn` / `sri_missing` at `https://js-cdn.lab.test/`: Mozilla HTTP Observatory 1.4.8 subresource-integrity test (CI header-truth run 45163435593, 2026-11-23): sri-not-implemented-but-external-scripts-loaded-securely; https://code.jquery.com/ui/1.12.1/jquery-ui.min.js without integrity. Missing from this manifest at first; the oracle surfaced it.

