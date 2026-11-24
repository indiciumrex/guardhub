# `default_creds` accuracy

Lab source revision `8c94317d417a`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 60.0% | 3 | 0 | 0 | 2 | 0 | 115 | 111 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `default_login_product` | 1 | 0 | 1 |
| `installer_exposed` | 2 | 0 | 1 |

## False positives (0)

None.

## False negatives (2)

- `dvwa` / `default_login_product` (outside the declared scope): /login.php is DVWA's login, whose documented default account is admin/password.
- `dvwa` / `installer_exposed` (outside the declared scope): /setup.php ('Database Setup', 'Create / Reset Database') is reachable without logging in.

## True positives (3)

- `drupal` / `installer_exposed` at `http://drupal.lab.test/core/install.php`: /core/install.php shows Drupal's web installer.
- `grafana` / `default_login_product` at `http://grafana.lab.test:3000/login`: Grafana login with the documented default admin/admin account, never changed.
- `wordpress` / `installer_exposed` at `http://wordpress.lab.test/wp-admin/install.php`: /wp-admin/install.php shows the WordPress install form.

