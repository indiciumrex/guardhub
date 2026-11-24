# `active_redirect` accuracy

Lab source revision `1a339b2b15bb`. Verdict: **NOT measured well enough: too few ground-truth findings to measure**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 1 | 0 | 0 | 0 | 0 | 8 | 7 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `open_redirect` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (1)

- `dvwa` / `open_redirect` at `http://dvwa.lab.test/vulnerabilities/open_redirect/source/low.php?redirect`: open_redirect low.php sends header('location: ' . $_GET['redirect']) for any value.

