# `active_sqli` accuracy

Lab source revision `1a339b2b15bb`. Verdict: **NOT measured well enough: too few ground-truth findings to measure**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 66.7% | 2 | 0 | 0 | 1 | 0 | 8 | 6 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `sql_injection` | 2 | 0 | 1 |

## False positives (0)

None.

## False negatives (1)

- `juice-shop` / `sql_injection` at `http://juice-shop.lab.test:3000/rest/products/search?q` (outside the declared scope): /rest/products/search builds a SQLite query from q by string concatenation (SQLITE_ERROR on a lone quote).

## True positives (2)

- `dvwa` / `sql_injection` at `http://dvwa.lab.test/vulnerabilities/sqli/?id`: sqli low.php puts $_GET['id'] into a quoted SQL string and prints mysqli_error() on failure.
- `dvwa` / `sql_injection` at `http://dvwa.lab.test/vulnerabilities/sqli_blind/?id`: sqli_blind low.php puts $_GET['id'] into a quoted SQL string; the page says whether a row exists (boolean-based).

