# `active_sqli` accuracy

Lab source revision `eaf1cdf4ef20`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 85.7% | 6 | 0 | 0 | 1 | 0 | 16 | 12 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `sql_injection` | 6 | 0 | 1 |

## False positives (0)

None.

## False negatives (1)

- `webgoat` / `sql_injection` at `http://webgoat.lab.test:8080/WebGoat/SqlInjectionMitigations/servers?column` (outside the declared scope): SQL Injection (mitigation) lesson 12: column is concatenated into ORDER BY.

## True positives (6)

- `av-sqli` / `sql_injection` at `http://av-sqli.lab.test/account?uid`: uid is concatenated into a quoted WHERE string; found answers 200, missing 404 (blind).
- `av-sqli` / `sql_injection` at `http://av-sqli.lab.test/item?id`: id is concatenated into WHERE id = ... and the SQLite error is printed.
- `av-sqli` / `sql_injection` at `http://av-sqli.lab.test/order?id`: id is concatenated into WHERE id = ...; errors are hidden, found and missing differ only in text (blind).
- `dvwa` / `sql_injection` at `http://dvwa.lab.test/vulnerabilities/sqli/?id`: sqli low.php puts $_GET['id'] into a quoted SQL string and prints mysqli_error() on failure.
- `dvwa` / `sql_injection` at `http://dvwa.lab.test/vulnerabilities/sqli_blind/?id`: sqli_blind low.php puts $_GET['id'] into a quoted SQL string; the page says whether a row exists (boolean-based).
- `juice-shop` / `sql_injection` at `http://juice-shop.lab.test:3000/rest/products/search?q`: Login-less SQLi challenge family: /rest/products/search builds a SQLite query from q by string concatenation (SQLITE_ERROR on a lone quote).

