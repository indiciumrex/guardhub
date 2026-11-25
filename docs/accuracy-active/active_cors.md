# `active_cors` accuracy

Lab source revision `e31b3c017884`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 9 | 0 | 0 | 0 | 0 | 26 | 23 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `cors_origin_reflected` | 9 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (9)

- `av-cors` / `cors_origin_reflected` at `http://av-cors.lab.test/api/me`: Access-Control-Allow-Origin echoes any Origin, with Access-Control-Allow-Credentials true.
- `av-cors` / `cors_origin_reflected` at `http://av-cors.lab.test/api/orders`: Origin null is granted with Access-Control-Allow-Credentials true.
- `av-cors` / `cors_origin_reflected` at `http://av-cors.lab.test/api/settings`: Access-Control-Allow-Origin echoes any Origin, with Access-Control-Allow-Credentials true.
- `av-cors2` / `cors_origin_reflected` at `http://av-cors2.lab.test/v1/notifications`: Any Origin is echoed with Access-Control-Allow-Credentials true, on a 401 answer.
- `av-cors2` / `cors_origin_reflected` at `http://av-cors2.lab.test/v1/profile`: Access-Control-Allow-Origin echoes any Origin, with Access-Control-Allow-Credentials true.
- `av-cors2` / `cors_origin_reflected` at `http://av-cors2.lab.test/v1/tokens`: Origin null is granted with Access-Control-Allow-Credentials true.
- `av-cors3` / `cors_origin_reflected` at `http://av-cors3.lab.test/data/export`: Access-Control-Allow-Origin echoes any Origin, with Access-Control-Allow-Credentials true (HTML).
- `av-cors3` / `cors_origin_reflected` at `http://av-cors3.lab.test/data/feed`: Access-Control-Allow-Origin echoes any Origin, with Access-Control-Allow-Credentials true.
- `av-cors3` / `cors_origin_reflected` at `http://av-cors3.lab.test/data/stats`: The allow-list admits Origin null, granted with Access-Control-Allow-Credentials true.

