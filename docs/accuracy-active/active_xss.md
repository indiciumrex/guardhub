# `active_xss` accuracy

Lab source revision `1a339b2b15bb`. Verdict: **NOT measured well enough: too few ground-truth findings to measure**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 1 | 0 | 0 | 0 | 0 | 8 | 7 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `reflected_xss` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (1)

- `dvwa` / `reflected_xss` at `http://dvwa.lab.test/vulnerabilities/xss_r/?name`: xss_r low.php echoes $_GET['name'] into the page without encoding.

