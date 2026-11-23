# `info_leak` accuracy

Lab source revision `925c3461ae43`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 83.3% | 10 | 0 | 0 | 2 | 0 | 97 | 91 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `directory_listing_enabled` | 1 | 0 | 1 |
| `framework_version_disclosed` | 4 | 0 | 0 |
| `server_version_disclosed` | 5 | 0 | 0 |
| `stack_trace_exposed` | 0 | 0 | 1 |

## False positives (0)

None.

## False negatives (2)

- `juice-shop` / `directory_listing_enabled` (outside the declared scope): /ftp, /encryptionkeys and /support/logs are browsable directory indexes (documented challenges). One issue: info_leak reports listings once per site by design.
- `juice-shop` / `stack_trace_exposed` (outside the declared scope): GET /rest/<unknown> returns 500 with an Express stack trace incl. /juice-shop/node_modules paths.

## True positives (10)

- `drupal` / `framework_version_disclosed` at `http://drupal.lab.test/core/install.php#header=X-Powered-By`: 'X-Powered-By: PHP/8.4.15'.
- `drupal` / `server_version_disclosed` at `http://drupal.lab.test/core/install.php#header=Server`: 'Server: Apache/2.4.65 (Debian)'.
- `dvwa` / `framework_version_disclosed` at `http://dvwa.lab.test/login.php#header=X-Powered-By`: Response header 'X-Powered-By: PHP/8.5.12'.
- `dvwa` / `server_version_disclosed` at `http://dvwa.lab.test/login.php#header=Server`: 'Server: Apache/2.4.69 (Debian)'; the 404 page footer shows the same string. One issue: Apache's footer follows ServerTokens, so one setting fixes both.
- `leaky` / `directory_listing_enabled` at `http://leaky.lab.test/backup/`: /backup/ is an nginx autoindex page.
- `leaky` / `server_version_disclosed` at `http://leaky.lab.test/#header=Server`: 'Server: nginx/1.27.5' (server_tokens on, the default).
- `phpmyadmin` / `framework_version_disclosed` at `http://phpmyadmin.lab.test/#header=X-Powered-By`: 'X-Powered-By: PHP/8.2.29'.
- `phpmyadmin` / `server_version_disclosed` at `http://phpmyadmin.lab.test/#header=Server`: 'Server: Apache/2.4.65 (Debian)'.
- `wordpress` / `framework_version_disclosed` at `http://wordpress.lab.test/wp-admin/install.php#header=X-Powered-By`: 'X-Powered-By: PHP/8.3.28'.
- `wordpress` / `server_version_disclosed` at `http://wordpress.lab.test/wp-admin/install.php#header=Server`: 'Server: Apache/2.4.65 (Debian)'.

