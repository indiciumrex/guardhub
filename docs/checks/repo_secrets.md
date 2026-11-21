# Check `repo_secrets` — credentials committed to a repository

- **Code:** `apps/scanner/internal/checks/repo_secrets.go`, rules in `secret_rules.go` · tests: `repo_secrets_test.go`
- **Target:** a connected GitHub repository (check-ids.json `"target": "repo"`) · **i18n:** `checks.json` → `repo_secrets` · **Module:** ships disabled (migration 0008)
- **Accuracy:** [`docs/accuracy/repo_secrets.md`](../accuracy/repo_secrets.md) · **Decision record:** [ADR-0006](../adr/0006-github-repo-scanning.md) §9

## What it detects

One finding per (file, rule). It carries the first line and how many distinct values of that
rule the file holds.

| Finding key | Severity | Params | When |
|---|---|---|---|
| `hardcoded_secret` | high | `secret_type`, `file`, `line`, `count` | a provider credential (rules below) |
| `test_mode_secret` | low | `secret_type`, `file`, `line`, `count` | a provider's test-mode key (Stripe `sk_test_`/`rk_test_`) |
| `generic_secret` | medium | `variable`, `file`, `line`, `count` | a long random value assigned to a secret-sounding name, when no provider rule matched that line |

**Provider rules:** each is a structure only that provider's credentials have, plus an entropy
floor.

| Group | Rules |
|---|---|
| Code hosting | GitHub PAT (classic and fine-grained), GitHub OAuth/refresh token, GitLab PAT |
| Cloud | AWS secret access key (next to an `aws…secret` name), Azure storage account key, DigitalOcean token |
| Messaging | Slack token, Slack incoming webhook, SendGrid key, Telegram bot token |
| Payments and stores | Stripe live secret/restricted key, Shopify token |
| Package registries | npm token, PyPI token |
| AI | OpenAI key, Anthropic key, Hugging Face token |
| Keys and URLs | PEM private keys (also `\n`-escaped inside JSON, e.g. service-account files); database or broker URLs with a password (postgres, mysql, mongodb, redis, amqp, mssql) |

**Deliberately absent:**

- Google browser API keys (`AIza…`) and Stripe publishable keys (public by design);
- GitHub installation and user-to-server tokens (they expire within hours);
- an AWS access key id on its own: it is not usable without its secret.

## What is not reported (false-positive discipline)

- **Test, fixture and example paths.**
  - Directories: `test`, `tests`, `__tests__`, `spec`, `testdata`, `fixtures`, `mocks`,
    `examples`, `samples`, `e2e`, `cypress`, `playwright`, `testing`, …
  - Files: `*_test.go`, `test_*.py`, `*_test.py`, `conftest.py`, `*.test.*`, `*.spec.*`.
  - Example or template files: `.env.example`, `*.sample.*`, `*.template`, `*.tmpl`, `*.dist`.

  The Phase 3 prompt names fake keys there as false positives. A real key in a test file is
  therefore a documented miss.
- **Generated and integrity data:**
  - lockfiles and `*.lock`, `go.sum` (integrity hashes);
  - `*.min.js`, `*.min.css`, `*.map`, `*.svg`.
- **Placeholder values:**
  - words: `example`, `sample`, `dummy`, `fake`, `your`, `xxxx`, `changeme`, `redacted`,
    `todo`, `mock`, `here`;
  - template syntax: `<…>`, `${…}`, `{{…}}`, `%s`, `****`, `...`;
  - sequences such as `123456` or `abcdef`;
  - runs of 5 identical characters;
  - fewer than 8 distinct characters in 16 or more.

  Generic values are also refused when they contain `secret`, `password`, `test`, `demo`,
  `default`, `local`, `admin`, ….
- **Local database URLs:** to `localhost`, loopback or private IPs, single-label hosts
  (compose services such as `db`), and `.local`, `.internal`, `.test`, `.example`,
  `example.com`.
- **Generic rule:**
  - **Names that are not secrets:** names ending in `_id`, `_url`, `_path`, `_name`, `_hash`,
    `_sha256`, `_digest`, `_checksum`, `public`, `publishable`, ….
  - **Values that are not credentials:** shorter than 16 characters, containing spaces, `/`,
    `$` or parentheses, with fewer than two character classes or no digit, or Shannon entropy
    below 3.5 bits per character.

## Evidence (never the secret)

- **Kind:** `repo_file`.
- **Location:** `https://github.com/<repo>/blob/HEAD/<file>#<rule>`, stable across commits for
  diffs.
- **Payload:** the rule, the file, the line, the commit, and the value masked to its last four
  characters (`****abcd`).
- **Never stored:** the line itself, the variable's surrounding code, or any longer excerpt.
- **No liveness check:** GuardHub never tries a found credential against the provider (§9.2).

## Scope and limits

- **Current files of the default branch only.** A secret deleted in a later commit but still in
  the git history is not seen yet (fast-follow).
- **Size limits:** files over 1 MiB and binary files are skipped. An incomplete snapshot fails
  the check with `repo_too_large`, still with its findings.
- **Gitleaks comparison** (validation lab):
  - On the trap repository, gitleaks v8.21.2 raises 9 alarms (fakes in tests, `.env.example`,
    a minified bundle, a digest, ids). This check raises none.
  - On the planted repositories, gitleaks confirms 14 of 18 secrets. The other 4 are formats
    it has no rule for: database URLs with passwords, an AWS secret without the AKIA id next to
    it, and a Telegram token.
