# `active_xss` accuracy

Lab source revision `03106298dd00`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 84.6% | 11 | 0 | 0 | 2 | 0 | 26 | 22 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `reflected_xss` | 11 | 0 | 2 |

## False positives (0)

None.

## False negatives (2)

- `av-xss` / `reflected_xss` at `http://av-xss.lab.test/lang?l` (outside the declared scope): l is written into a JavaScript string inside a script element without encoding.
- `webgoat` / `reflected_xss` at `http://webgoat.lab.test:8080/WebGoat/CrossSiteScripting/attack5a?field1` (outside the declared scope): Cross Site Scripting lesson 7: field1 comes back in the JSON feedback that the lesson page renders as HTML.

## True positives (11)

- `av-xss` / `reflected_xss` at `http://av-xss.lab.test/greet?who`: who is written into a single-quoted title attribute without encoding.
- `av-xss` / `reflected_xss` at `http://av-xss.lab.test/profile?name`: name is written into a double-quoted value attribute without encoding.
- `av-xss` / `reflected_xss` at `http://av-xss.lab.test/search?q`: q is written into the page text without encoding.
- `av-xss2` / `reflected_xss` at `http://av-xss2.lab.test/err?code`: code is written unencoded into an HTTP 400 error page.
- `av-xss2` / `reflected_xss` at `http://av-xss2.lab.test/find?term`: term passes a blocklist that removes script tags only; other elements are written unencoded.
- `av-xss2` / `reflected_xss` at `http://av-xss2.lab.test/hello?name`: name passes a home-made escape that encodes & only.
- `av-xss2` / `reflected_xss` at `http://av-xss2.lab.test/json-html?q`: q is written unencoded into a JSON body served as text/html.
- `av-xss2` / `reflected_xss` at `http://av-xss2.lab.test/list?dir`: dir is written unencoded into a double-quoted href attribute.
- `av-xss2` / `reflected_xss` at `http://av-xss2.lab.test/page?ref`: ref is written unencoded into the page text (id, the other parameter, is validated).
- `av-xss2` / `reflected_xss` at `http://av-xss2.lab.test/tag?label`: label has its quotes encoded but not < and >, inside page text.
- `dvwa` / `reflected_xss` at `http://dvwa.lab.test/vulnerabilities/xss_r/?name`: xss_r low.php echoes $_GET['name'] into the page without encoding.

