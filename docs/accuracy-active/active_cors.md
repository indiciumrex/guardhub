# `active_cors` accuracy

Lab source revision `eaf1cdf4ef20`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 3 | 0 | 0 | 0 | 0 | 16 | 15 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `cors_origin_reflected` | 3 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (3)

- `av-cors` / `cors_origin_reflected` at `http://av-cors.lab.test/api/me`: Access-Control-Allow-Origin echoes any Origin, with Access-Control-Allow-Credentials true.
- `av-cors` / `cors_origin_reflected` at `http://av-cors.lab.test/api/orders`: Origin null is granted with Access-Control-Allow-Credentials true.
- `av-cors` / `cors_origin_reflected` at `http://av-cors.lab.test/api/settings`: Access-Control-Allow-Origin echoes any Origin, with Access-Control-Allow-Credentials true.

