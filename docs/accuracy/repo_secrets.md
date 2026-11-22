# `repo_secrets` accuracy

Lab source revision `d37b6a296298`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 18 | 0 | 0 | 0 | 0 | 11 | 9 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `generic_secret` | 2 | 0 | 0 |
| `hardcoded_secret` | 15 | 0 | 0 |
| `test_mode_secret` | 1 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (18)

- `rp-secrets-app` / `generic_secret` at `https://github.com/lab/rp-secrets-app/blob/HEAD/src/config.ts#generic`: planted: jwtSecret assigned a 32-char random value; gitleaks v8.21.2: generic-api-key
- `rp-secrets-app` / `generic_secret` at `https://github.com/lab/rp-secrets-app/blob/HEAD/src/settings.py#generic`: planted: Django SECRET_KEY assigned a 32-char random value; gitleaks v8.21.2: generic-api-key
- `rp-secrets-app` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-app/blob/HEAD/.env#sendgrid_key`: planted: committed .env with a SendGrid key; gitleaks v8.21.2: sendgrid-api-token
- `rp-secrets-app` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-app/blob/HEAD/.env#stripe_live_secret`: planted: committed .env with a live Stripe secret key; gitleaks v8.21.2: stripe-access-token
- `rp-secrets-app` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-app/blob/HEAD/config/database.js#database_url`: planted: postgres URL with a password to the remote host db.shop-prod.io (gitleaks has no URL-credential rule); verified by construction (labfixture generator)
- `rp-secrets-app` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-app/blob/HEAD/deploy/server.key#private_key`: planted: PEM private key file; gitleaks v8.21.2: private-key
- `rp-secrets-app` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-app/blob/HEAD/scripts/release.sh#github_pat`: planted: GitHub personal access token in a script; gitleaks v8.21.2: github-pat
- `rp-secrets-app` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-app/blob/HEAD/src/ai/summarize.py#openai_key`: planted: OpenAI project key (T3BlbkFJ marker); gitleaks v8.21.2: generic-api-key
- `rp-secrets-app` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-app/blob/HEAD/src/alerts.js#slack_webhook`: planted: Slack incoming webhook URL; gitleaks v8.21.2: slack-webhook-url
- `rp-secrets-app` / `test_mode_secret` at `https://github.com/lab/rp-secrets-app/blob/HEAD/src/payments/checkout.ts#stripe_test_secret`: planted: Stripe TEST-mode secret key: low (no live money or data); gitleaks v8.21.2: stripe-access-token
- `rp-secrets-infra` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-infra/blob/HEAD/.npmrc#npm_token`: planted: npm automation token in .npmrc; gitleaks v8.21.2: npm-access-token
- `rp-secrets-infra` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-infra/blob/HEAD/ansible/group_vars/all.yml#gitlab_pat`: planted: GitLab personal access token; gitleaks v8.21.2: gitlab-pat
- `rp-secrets-infra` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-infra/blob/HEAD/bot/config.json#slack_token`: planted: Slack bot token; gitleaks v8.21.2: slack-legacy-bot-token
- `rp-secrets-infra` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-infra/blob/HEAD/ci/notify.py#telegram_bot_token`: planted: Telegram bot token <id>:AA<33> (gitleaks' rule needs the keyword on the same line); verified by construction (labfixture generator)
- `rp-secrets-infra` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-infra/blob/HEAD/docker-compose.prod.yml#database_url`: planted: rediss URL with a password to cache.infra-prod.net (no gitleaks rule); verified by construction (labfixture generator)
- `rp-secrets-infra` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-infra/blob/HEAD/k8s/do-secret.yaml#digitalocean_token`: planted: DigitalOcean token in a committed Kubernetes Secret; gitleaks v8.21.2: digitalocean-pat
- `rp-secrets-infra` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-infra/blob/HEAD/notebooks/explore.ipynb#huggingface_token`: planted: Hugging Face token in a notebook cell; gitleaks v8.21.2: huggingface-access-token
- `rp-secrets-infra` / `hardcoded_secret` at `https://github.com/lab/rp-secrets-infra/blob/HEAD/terraform/prod.tfvars#aws_secret_access_key`: planted: aws_secret_access_key = 40-char key (gitleaks keys on the AKIA id, here AWS's documented EXAMPLE id, which it allowlists); verified by construction (labfixture generator)

