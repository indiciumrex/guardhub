# Check `js_secrets` — credentials shipped to every visitor's browser

- **Code:** `apps/scanner/internal/checks/js_secrets.go` · tests: `js_secrets_test.go`
- **Rules:** `secret_rules.go`, shared with [`repo_secrets`](repo_secrets.md)
- **i18n:** `checks.json` → `js_secrets` (en, tr; the other locales are in the translation queue, §7.5)
- **Module:** ships disabled (migration 0015)
- **Accuracy:** [`docs/accuracy/js_secrets.md`](../accuracy/js_secrets.md) · **Decision record:** [ADR-0007](../adr/0007-phase4a-depth-methodology.md) ("content signals: keys in JS bundles")

## What it detects

| Finding key | Severity | Params | When |
|---|---|---|---|
| `secret_in_javascript` | high | `secret_type`, `script`, `count` | a live credential (one of `repo_secrets`' `hardcoded_secret` rules) in the home page's HTML or one of its same-origin scripts |
| `test_secret_in_javascript` | low | `secret_type`, `script`, `count` | a test-mode credential (for example a Stripe `sk_test_` key) in the same places |

One finding per (page or script, rule). The location is `<url>#<rule>`.

**Severity (ADR-0007 rubric):**

- **high (`secret_in_javascript`):** an outsider can use the credential directly. GuardHub does
  not try it, because that would be an active test, so it does not claim "critical" (a proven
  working secret).
- **low (`test_secret_in_javascript`):** test-mode keys reach only the provider's test
  environment.

## Rules

`repo_secrets`' provider rules apply: a fixed prefix or structure only that provider's credentials
have, with its placeholder and entropy filters. The rules cover:

- **Code hosts and package registries:** GitHub and GitLab tokens, npm and PyPI tokens.
- **Messaging:** Slack tokens and webhooks, Telegram bot tokens, SendGrid keys.
- **Payments and commerce:** Stripe secret and restricted keys, Shopify access tokens.
- **Cryptographic material:** private keys.
- **AI providers:** OpenAI and Anthropic keys, Hugging Face tokens.
- **Infrastructure:** AWS secret keys, Azure storage account keys, DigitalOcean tokens and
  database URLs with a password.

**Not reported:**

- **Keys meant for browsers:** Google browser API keys, Stripe publishable keys (`pk_`) and
  Firebase web configuration. No rule exists for them.
- **The generic "password = …" rule:** minified code is full of such names with labels as values.
- **Placeholders:** `ghp_xxxx…`, `your-key-here` and the like.

## Scope

- **Read:** the home page's HTML (after same-host redirects), which includes inline scripts and
  attributes.
- **Scripts:** the first 10 `<script src>` tags. At most 6 same-origin scripts are fetched, each
  read up to the probe's 256 KiB. An HTML answer is an error page, not the script.
- **Cross-origin scripts are never fetched.**
- **Evidence holds masked values only.**

## Validation

**Lab targets** (`ks-*`, `nginx/ks.conf`): `clean`'s headers and TLS. The pages and scripts in
`test_corpus/ks/` carry secret **templates**, which `labrepo materialize` (`ks-init`) fills at lab
start, so no credential-shaped string is committed.

- **Positives:**
  - a GitHub token in a script (`ks-github`);
  - a Stripe live key in an inline script (`ks-inline`);
  - a private key in a template literal (`ks-privkey`);
  - a Stripe test key (`ks-testkey`).
- **Negative** (`ks-public`): a publishable `pk_live_` key, an all-x placeholder and form labels.

**Independent truth:** `test_corpus/oracles/secrets/oracle_secrets.py`, run by
`oracles/headers/run.sh` in CI's `header-truth` job.

- **Fetching:** curl and Python's HTML parser fetch the page and every same-origin script.
- **Scanning:** gitleaks v8.21.2 scans them unmodified with its default rules. This is the same
  release CI's secret scan uses.
- **Mapping:** its findings count only for the credential kinds declared above (rule mapping in
  the oracle). Its publishable-key and generic rules are listed in the notes only.

`compare.py` fails the job on any manifest mismatch.
