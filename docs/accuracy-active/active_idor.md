# `active_idor` accuracy

Lab source revision `03106298dd00`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 8 | 0 | 0 | 0 | 0 | 26 | 24 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `idor_cross_account_read` | 8 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (8)

- `av-idor` / `idor_cross_account_read` at `http://av-idor.lab.test/invoice`: /invoice?id= returns any invoice to any signed-in account (no owner check).
- `av-idor` / `idor_cross_account_read` at `http://av-idor.lab.test/message`: /message?msg_id= returns any message to any signed-in account (no owner check).
- `av-idor` / `idor_cross_account_read` at `http://av-idor.lab.test/profile/1001`: /profile/<id> returns any profile to any signed-in account (no owner check).
- `av-idor2` / `idor_cross_account_read` at `http://av-idor2.lab.test/address`: /address?addr_no= returns any address to any signed-in account (no owner check).
- `av-idor2` / `idor_cross_account_read` at `http://av-idor2.lab.test/api/orders/5001`: /api/orders/<id> returns any order as JSON to any signed-in account (no owner check).
- `av-idor2` / `idor_cross_account_read` at `http://av-idor2.lab.test/download`: /download?doc_id=<uuid> returns any document to any signed-in account (no owner check).
- `av-idor2` / `idor_cross_account_read` at `http://av-idor2.lab.test/statement`: /statement?account_key= returns any statement to any signed-in account (no owner check).
- `av-idor2` / `idor_cross_account_read` at `http://av-idor2.lab.test/ticket`: /ticket?ref= returns any ticket to any signed-in account (no owner check).

