# `active_redirect` accuracy

Lab source revision `e31b3c017884`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 84.6% | 11 | 0 | 0 | 2 | 0 | 26 | 21 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `open_redirect` | 11 | 0 | 2 |

## False positives (0)

None.

## False negatives (2)

- `av-redirect` / `open_redirect` at `http://av-redirect.lab.test/jump?dest` (outside the declared scope): dest goes into a meta refresh URL (encoded for HTML, never checked).
- `juice-shop` / `open_redirect` at `http://juice-shop.lab.test:3000/redirect?to` (outside the declared scope): Allow-listed Redirect challenge: /redirect accepts any URL that merely contains an allow-listed one (substring check).

## True positives (11)

- `av-redirect` / `open_redirect` at `http://av-redirect.lab.test/go?url`: url goes into Location unchecked.
- `av-redirect` / `open_redirect` at `http://av-redirect.lab.test/login?next`: next only has to start with a slash, so //other-host/ is accepted (protocol-relative).
- `av-redirect` / `open_redirect` at `http://av-redirect.lab.test/out?to`: to goes into the Refresh header unchecked.
- `av-redirect2` / `open_redirect` at `http://av-redirect2.lab.test/auth/callback?redirect_uri`: redirect_uri goes into Location; only javascript: is refused.
- `av-redirect2` / `open_redirect` at `http://av-redirect2.lab.test/r301?u`: u goes into Location (301) unchecked.
- `av-redirect2` / `open_redirect` at `http://av-redirect2.lab.test/r303?continue`: continue goes into Location (303) unchecked.
- `av-redirect2` / `open_redirect` at `http://av-redirect2.lab.test/r307?return`: return goes into Location (307) unchecked.
- `av-redirect3` / `open_redirect` at `http://av-redirect3.lab.test/bye?returnTo`: returnTo goes into Location unchecked.
- `av-redirect3` / `open_redirect` at `http://av-redirect3.lab.test/r?next`: next loses a leading http:// or https:// once; //other-host/ is not touched (protocol-relative).
- `av-redirect3` / `open_redirect` at `http://av-redirect3.lab.test/to?url`: url goes into the Refresh header (0;URL='...') unchecked.
- `dvwa` / `open_redirect` at `http://dvwa.lab.test/vulnerabilities/open_redirect/source/low.php?redirect`: open_redirect low.php sends header('location: ' . $_GET['redirect']) for any value.

