# `http_hardening` accuracy

Lab source revision `d37b6a296298`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 6 | 0 | 0 | 0 | 0 | 67 | 61 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `cors_any_origin_with_credentials` | 1 | 0 | 0 |
| `cors_null_origin_with_credentials` | 1 | 0 | 0 |
| `csp_ineffective` | 2 | 0 | 0 |
| `referrer_policy_unsafe_url` | 1 | 0 | 0 |
| `xfo_ineffective` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (6)

- `hh-cors-cred` / `cors_any_origin_with_credentials` at `http://hh-cors-cred.lab.test/`: Origin https://guardhub-cors-check.invalid is echoed in Access-Control-Allow-Origin with Allow-Credentials: true.
- `hh-cors-null` / `cors_null_origin_with_credentials` at `http://hh-cors-null.lab.test/`: Origin null gets Access-Control-Allow-Origin: null + Allow-Credentials: true; other origins are not echoed.
- `hh-csp-weak` / `csp_ineffective` at `http://hh-csp-weak.lab.test/`: script-src 'self' 'unsafe-inline' https: with no nonce/hash and no strict-dynamic.
- `hh-referrer` / `referrer_policy_unsafe_url` at `http://hh-referrer.lab.test/`: Referrer-Policy: unsafe-url (the only policy token).
- `hh-xfo-allowfrom` / `xfo_ineffective` at `http://hh-xfo-allowfrom.lab.test/`: X-Frame-Options: ALLOW-FROM https://partner.lab.test, CSP default-src 'self' without frame-ancestors.
- `phpmyadmin` / `csp_ineffective` at `http://phpmyadmin.lab.test/`: Its CSP has script-src 'self' 'unsafe-inline' 'unsafe-eval' with no nonce or hash: injected inline scripts would run.

