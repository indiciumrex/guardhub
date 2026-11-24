# `active_idor` accuracy

Lab source revision `eaf1cdf4ef20`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 3 | 0 | 0 | 0 | 0 | 16 | 15 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `idor_cross_account_read` | 3 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (3)

- `av-idor` / `idor_cross_account_read` at `http://av-idor.lab.test/invoice`: /invoice?id= returns any invoice to any signed-in account (no owner check).
- `av-idor` / `idor_cross_account_read` at `http://av-idor.lab.test/message`: /message?msg_id= returns any message to any signed-in account (no owner check).
- `av-idor` / `idor_cross_account_read` at `http://av-idor.lab.test/profile/1001`: /profile/<id> returns any profile to any signed-in account (no owner check).

