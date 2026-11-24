# `active_xss` accuracy

Lab source revision `eaf1cdf4ef20`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 66.7% | 4 | 0 | 0 | 2 | 0 | 16 | 13 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `reflected_xss` | 4 | 0 | 2 |

## False positives (0)

None.

## False negatives (2)

- `av-xss` / `reflected_xss` at `http://av-xss.lab.test/lang?l` (outside the declared scope): l is written into a JavaScript string inside a script element without encoding.
- `webgoat` / `reflected_xss` at `http://webgoat.lab.test:8080/WebGoat/CrossSiteScripting/attack5a?field1` (outside the declared scope): Cross Site Scripting lesson 7: field1 comes back in the JSON feedback that the lesson page renders as HTML.

## True positives (4)

- `av-xss` / `reflected_xss` at `http://av-xss.lab.test/greet?who`: who is written into a single-quoted title attribute without encoding.
- `av-xss` / `reflected_xss` at `http://av-xss.lab.test/profile?name`: name is written into a double-quoted value attribute without encoding.
- `av-xss` / `reflected_xss` at `http://av-xss.lab.test/search?q`: q is written into the page text without encoding.
- `dvwa` / `reflected_xss` at `http://dvwa.lab.test/vulnerabilities/xss_r/?name`: xss_r low.php echoes $_GET['name'] into the page without encoding.

