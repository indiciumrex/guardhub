# `security_headers` accuracy

Lab source revision `a38ed80ac882+wip`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 15 | 0 | 0 | 0 | 0 | 21 | 15 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `clickjacking_unprotected` | 4 | 0 | 0 |
| `cookie_flags_missing` | 1 | 0 | 0 |
| `csp_missing` | 6 | 0 | 0 |
| `nosniff_missing` | 4 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (15)

- `drupal` / `clickjacking_unprotected` at `http://drupal.lab.test/core/install.php`: The installer page sends neither X-Frame-Options nor frame-ancestors.
- `drupal` / `csp_missing` at `http://drupal.lab.test/core/install.php`: The installer page sends no Content-Security-Policy.
- `drupal` / `nosniff_missing` at `http://drupal.lab.test/core/install.php`: The installer page sends no X-Content-Type-Options.
- `dvwa` / `clickjacking_unprotected` at `http://dvwa.lab.test/login.php`: /login.php sends neither X-Frame-Options nor CSP frame-ancestors.
- `dvwa` / `cookie_flags_missing` at `http://dvwa.lab.test/login.php#set-cookie=security`: Cookie 'security' is set with HttpOnly but without SameSite.
- `dvwa` / `csp_missing` at `http://dvwa.lab.test/login.php`: /login.php (the page / redirects to) sends no Content-Security-Policy.
- `dvwa` / `nosniff_missing` at `http://dvwa.lab.test/login.php`: /login.php sends no X-Content-Type-Options.
- `grafana` / `csp_missing` at `http://grafana.lab.test:3000/login`: /login sends no Content-Security-Policy.
- `juice-shop` / `csp_missing` at `http://juice-shop.lab.test:3000/`: GET / has no Content-Security-Policy (only XCTO, XFO SAMEORIGIN, Feature-Policy).
- `leaky` / `clickjacking_unprotected` at `http://leaky.lab.test/`: Neither X-Frame-Options nor frame-ancestors.
- `leaky` / `csp_missing` at `http://leaky.lab.test/`: No Content-Security-Policy.
- `leaky` / `nosniff_missing` at `http://leaky.lab.test/`: No X-Content-Type-Options.
- `wordpress` / `clickjacking_unprotected` at `http://wordpress.lab.test/wp-admin/install.php`: The installer page sends neither X-Frame-Options nor frame-ancestors.
- `wordpress` / `csp_missing` at `http://wordpress.lab.test/wp-admin/install.php`: The installer page sends no Content-Security-Policy.
- `wordpress` / `nosniff_missing` at `http://wordpress.lab.test/wp-admin/install.php`: The installer page sends no X-Content-Type-Options.

