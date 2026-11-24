# `exposed_env` accuracy

Lab source revision `8c94317d417a`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 3 | 0 | 0 | 0 | 0 | 115 | 114 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `cloud_credentials_exposed` | 1 | 0 | 0 |
| `env_file_exposed` | 1 | 0 | 0 |
| `git_repository_exposed` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (3)

- `leaky` / `cloud_credentials_exposed` at `http://leaky.lab.test/.aws/credentials`: /.aws/credentials is served with an access key pair.
- `leaky` / `env_file_exposed` at `http://leaky.lab.test/.env`: /.env is served (DATABASE_URL, STRIPE_SECRET_KEY, APP_KEY).
- `leaky` / `git_repository_exposed` at `http://leaky.lab.test/.git/HEAD`: /.git/HEAD and /.git/config are served.

