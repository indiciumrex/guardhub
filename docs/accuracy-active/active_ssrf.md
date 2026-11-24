# `active_ssrf` accuracy

Lab source revision `eaf1cdf4ef20`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 5 | 0 | 0 | 0 | 0 | 16 | 14 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `ssrf_confirmed` | 5 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (5)

- `av-ssrf` / `ssrf_confirmed` at `http://av-ssrf.lab.test/fetch?url`: the server fetches url.
- `av-ssrf` / `ssrf_confirmed` at `http://av-ssrf.lab.test/hook?callback`: the server fetches callback.
- `av-ssrf` / `ssrf_confirmed` at `http://av-ssrf.lab.test/img?u`: the server fetches u (its default value is a URL).
- `av-ssrf` / `ssrf_confirmed` at `http://av-ssrf.lab.test/preview?src`: the server fetches src.
- `dvwa` / `ssrf_confirmed` at `http://dvwa.lab.test/vulnerabilities/fi/?page`: fi low.php includes $_GET['page']; Apache's PHP includes remote URLs, so the server fetches any URL it is given.

