# `active_redirect` accuracy

Lab source revision `eaf1cdf4ef20`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 66.7% | 4 | 0 | 0 | 2 | 0 | 16 | 13 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `open_redirect` | 4 | 0 | 2 |

## False positives (0)

None.

## False negatives (2)

- `av-redirect` / `open_redirect` at `http://av-redirect.lab.test/jump?dest` (outside the declared scope): dest goes into a meta refresh URL (encoded for HTML, never checked).
- `juice-shop` / `open_redirect` at `http://juice-shop.lab.test:3000/redirect?to` (outside the declared scope): Allow-listed Redirect challenge: /redirect accepts any URL that merely contains an allow-listed one (substring check).

## True positives (4)

- `av-redirect` / `open_redirect` at `http://av-redirect.lab.test/go?url`: url goes into Location unchecked.
- `av-redirect` / `open_redirect` at `http://av-redirect.lab.test/login?next`: next only has to start with a slash, so //other-host/ is accepted (protocol-relative).
- `av-redirect` / `open_redirect` at `http://av-redirect.lab.test/out?to`: to goes into the Refresh header unchecked.
- `dvwa` / `open_redirect` at `http://dvwa.lab.test/vulnerabilities/open_redirect/source/low.php?redirect`: open_redirect low.php sends header('location: ' . $_GET['redirect']) for any value.

