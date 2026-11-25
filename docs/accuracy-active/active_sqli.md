# `active_sqli` accuracy

Lab source revision `03106298dd00`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 93.3% | 14 | 0 | 0 | 1 | 0 | 26 | 21 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `sql_injection` | 14 | 0 | 1 |

## False positives (0)

None.

## False negatives (1)

- `webgoat` / `sql_injection` at `http://webgoat.lab.test:8080/WebGoat/SqlInjectionMitigations/servers?column` (outside the declared scope): SQL Injection (mitigation) lesson 12: column is concatenated into ORDER BY.

## True positives (14)

- `av-sqli` / `sql_injection` at `http://av-sqli.lab.test/account?uid`: uid is concatenated into a quoted WHERE string; found answers 200, missing 404 (blind).
- `av-sqli` / `sql_injection` at `http://av-sqli.lab.test/item?id`: id is concatenated into WHERE id = ... and the SQLite error is printed.
- `av-sqli` / `sql_injection` at `http://av-sqli.lab.test/order?id`: id is concatenated into WHERE id = ...; errors are hidden, found and missing differ only in text (blind).
- `av-sqli2` / `sql_injection` at `http://av-sqli2.lab.test/item?id`: id is concatenated into WHERE id = (...); errors are hidden, found answers 200, missing 404 (blind).
- `av-sqli2` / `sql_injection` at `http://av-sqli2.lab.test/lookup?email`: email is concatenated into a quoted WHERE string; errors are hidden and the linked value is an e-mail address (blind).
- `av-sqli2` / `sql_injection` at `http://av-sqli2.lab.test/price?max`: max is concatenated into WHERE price <= ... and the SQLite message is shown.
- `av-sqli2` / `sql_injection` at `http://av-sqli2.lab.test/review?id`: id is concatenated into WHERE id = ...; errors are hidden and the linked value is 3, so a condition must keep 3 to answer like the page (blind).
- `av-sqli2` / `sql_injection` at `http://av-sqli2.lab.test/sorted?order`: order is concatenated into ORDER BY and the SQLite message is shown.
- `av-sqli2` / `sql_injection` at `http://av-sqli2.lab.test/stock?sku`: sku is concatenated into WHERE (id = ...); errors are hidden, found and missing differ only in text (blind).
- `av-sqli2` / `sql_injection` at `http://av-sqli2.lab.test/tag?name`: name is concatenated into a quoted LIKE pattern and the SQLite message is shown as SQLITE_ERROR.
- `av-sqli2` / `sql_injection` at `http://av-sqli2.lab.test/user?name`: name is concatenated into a quoted WHERE string and the SQLite message is shown.
- `dvwa` / `sql_injection` at `http://dvwa.lab.test/vulnerabilities/sqli/?id`: sqli low.php puts $_GET['id'] into a quoted SQL string and prints mysqli_error() on failure.
- `dvwa` / `sql_injection` at `http://dvwa.lab.test/vulnerabilities/sqli_blind/?id`: sqli_blind low.php puts $_GET['id'] into a quoted SQL string; the page says whether a row exists (boolean-based).
- `juice-shop` / `sql_injection` at `http://juice-shop.lab.test:3000/rest/products/search?q`: Login-less SQLi challenge family: /rest/products/search builds a SQLite query from q by string concatenation (SQLITE_ERROR on a lone quote).

