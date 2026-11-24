# `js_secrets` accuracy

Lab source revision `8c94317d417a`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 4 | 0 | 0 | 0 | 0 | 115 | 111 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `secret_in_javascript` | 3 | 0 | 0 |
| `test_secret_in_javascript` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (4)

- `ks-github` / `secret_in_javascript` at `https://ks-github.lab.test/static/app.js#github_pat`: gitleaks v8.21.2 default rules (local lab run 2026-11-23): github-pat in /static/app.js line 1 (the planted GitHub personal access token).
- `ks-inline` / `secret_in_javascript` at `https://ks-inline.lab.test/#stripe_live_secret`: gitleaks v8.21.2 default rules (local lab run 2026-11-23): stripe-access-token, sk_live_ prefix, in the home page's inline script (line 2).
- `ks-privkey` / `secret_in_javascript` at `https://ks-privkey.lab.test/static/config.js#private_key`: gitleaks v8.21.2 default rules (local lab run 2026-11-23): private-key in /static/config.js (the planted RSA private key in a template literal).
- `ks-testkey` / `test_secret_in_javascript` at `https://ks-testkey.lab.test/static/pay.js#stripe_test_secret`: gitleaks v8.21.2 default rules (local lab run 2026-11-23): stripe-access-token, sk_test_ prefix, in /static/pay.js line 1.

