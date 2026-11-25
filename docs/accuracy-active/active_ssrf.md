# `active_ssrf` accuracy

Lab source revision `03106298dd00`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 10 | 0 | 0 | 0 | 0 | 26 | 23 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `ssrf_confirmed` | 10 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (10)

- `av-ssrf` / `ssrf_confirmed` at `http://av-ssrf.lab.test/fetch?url`: the server fetches url.
- `av-ssrf` / `ssrf_confirmed` at `http://av-ssrf.lab.test/hook?callback`: the server fetches callback.
- `av-ssrf` / `ssrf_confirmed` at `http://av-ssrf.lab.test/img?u`: the server fetches u (its default value is a URL).
- `av-ssrf` / `ssrf_confirmed` at `http://av-ssrf.lab.test/preview?src`: the server fetches src.
- `av-ssrf2` / `ssrf_confirmed` at `http://av-ssrf2.lab.test/api/webhook-test?webhook`: the server fetches webhook.
- `av-ssrf2` / `ssrf_confirmed` at `http://av-ssrf2.lab.test/proxy?target`: the server fetches target.
- `av-ssrf2` / `ssrf_confirmed` at `http://av-ssrf2.lab.test/rss?feed`: the server fetches feed.
- `av-ssrf2` / `ssrf_confirmed` at `http://av-ssrf2.lab.test/share?q`: the server fetches q (a link preview; the parameter name says nothing, its value is a URL).
- `av-ssrf2` / `ssrf_confirmed` at `http://av-ssrf2.lab.test/thumb?image_url`: the server fetches image_url.
- `dvwa` / `ssrf_confirmed` at `http://dvwa.lab.test/vulnerabilities/fi/?page`: fi low.php includes $_GET['page']; Apache's PHP includes remote URLs, so the server fetches any URL it is given.

