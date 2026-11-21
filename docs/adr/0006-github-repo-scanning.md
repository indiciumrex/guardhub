# ADR-0006 — Repository scanning: GitHub App, per-scan tokens, in-memory snapshots, OSV

- **Status:** accepted
- **Date:** 2026-11-21
- **Context sections:** GUARDHUB_STANDARDS.md §2.3, §2.9, §3, §6, §9.1–§9.3, §11 (Phase 2 "repo bağlama");
  ADR-0002 (queue protocol), ADR-0004 (accuracy gate)

## Context

Phase 3 ("Repo Zekâsı") lets a user connect their own GitHub repositories. GuardHub then reports
**vulnerable dependencies** (known CVEs/advisories) and **secrets committed to the code**. This is
the first time GuardHub reads a customer's source code, so the standards' least-privilege,
least-data rules (§2.9, §9.3) decide most of the design:

- read-only access, to the repositories the user chose;
- the code is never stored;
- only masked findings are stored;
- the user can revoke access with one click;
- every connection change and repo scan is audited.

## Decision

### 1. GitHub App, not an OAuth app

- **Permissions:** `contents: read` and `metadata: read` (GitHub adds metadata to every App).
  Nothing else: no write permission, no webhooks, no user-level scopes.
- **Which repositories:** the user picks them on GitHub's install screen. We tell them to choose
  "Only select repositories". If they pick "All repositories", GuardHub still scans only the
  repositories they add as projects.
- **Why not OAuth:** an OAuth app with the `repo` scope gets read *and write* access to every
  repository the user can see. That is more than we need, and it breaks the prompt's "en az
  yetki".

### 2. No GitHub token is stored at all

- **What is stored:** GuardHub keeps only the **installation id** (not a secret) and the GitHub
  account's login.
- **Per scan:** the API mints an installation access token with the App's private key:
  - it lives one hour;
  - it is narrowed to `repository_ids: [that repo]` and `permissions: {contents: read}`.

  The token goes into Redis under a one-time key with a 10-minute TTL (`gh:repo-token:<job_id>`);
  it is never in the job stream. The scanner reads it with `GETDEL` and revokes it at GitHub
  (`DELETE /installation/token`) when the scan ends, success or not.
- **This goes beyond "token şifreli saklanır":** there is no long-lived token to encrypt, leak or
  rotate.
- **The App private key:** it can mint tokens for every installation.
  - It lives only in a server file, `/opt/guardhub/shared/github-app/app.pem` (mode 0400, owned
    by the API image's user).
  - It is mounted read-only into `api` and `api-jobs` (scheduled scans mint tokens too).
  - It is never in the repository (`.gitignore` refuses it), the database or the scanner.
- **How the API reaches GitHub:** `api` and `api-worker` have no internet access, and that stays
  so. GitHub is reached through a CONNECT-only egress proxy (`scanner egress-proxy`, service
  `github-egress`). It tunnels TLS to exactly `api.github.com:443` and `github.com:443` and
  refuses private addresses. It sees host names only, never tokens or content.
- **The OAuth client secret:** in `.env`, like the other secrets.

### 3. Binding an installation to a GuardHub account must be proven

- **The threat:** the install callback carries `installation_id` in the URL, and installation ids
  are guessable. If GuardHub trusted that parameter, an attacker could attach a victim's
  installation to the attacker's GuardHub account and read the victim's findings, which include
  masked secrets.
- **The fix:** the App uses GitHub's "request user authorization (OAuth) during installation".
  1. The callback carries a one-time `code` and our `state`. The state is random, kept in Redis
     for 10 minutes and bound to the GuardHub user who started the flow.
  2. The API exchanges the code for a user token.
  3. It confirms that `installation_id` appears in `GET /user/installations` for that GitHub
     user.
  4. It revokes the user token right away.
- **One owner per installation:** an installation belongs to one GuardHub account; a second
  account gets 409. Team accounts are a later phase.

### 4. Revocation

- **"Disconnect" in GuardHub:**
  - uninstalls the App at GitHub (`DELETE /app/installations/{id}`, which kills every token it
    ever minted);
  - marks the row revoked and stops scans of its repo projects (their history stays, like a
    site project that lost ownership);
  - writes an audit record.
- **Uninstalling on GitHub directly:** the next token mint returns 404 or 403. GuardHub then marks
  the installation revoked and pauses the projects. No webhook is needed, so none is enabled.

### 5. A repository is a project of kind `repo`

- **The model:** `projects.kind` becomes `site` (default) or `repo`. A repo project carries
  `repo_full_name`, `repo_id` (GitHub's stable numeric id) and `github_installation_id`.
- **Why:** history, compare, scheduled scans, alerts and RLS all work unchanged.
- **Ownership proof:** the installation (ownership method `github_app`). It is re-proven on every
  scan, because minting the narrowed token fails if access is gone.
- **Repo checks are their own catalog target:** `check-ids.json` marks them `"target": "repo"`.
  Site scans never run them and repo scans run only them.

### 6. The scanner reads a snapshot in memory, never on disk

- **What is read:** one request for the default branch's tarball. The gzip/tar stream is read
  entry by entry into memory.
- **Caps:**

  | What | Cap |
  |---|---|
  | Tarball stream | 128 MiB |
  | Text file kept | 1 MiB (lockfiles 16 MiB) |
  | All kept files | 48 MiB |
  | Files | 50,000 |

- **Skipped:** binary files (NUL in the first 8 KiB) and vendored directories (`node_modules/`,
  `vendor/`, `.venv/` and others).
- **Over a cap:** the checks still run on what was read. The check then ends with the error code
  `repo_too_large`, so the report never pretends a partial scan was complete.
- **After the scan:** the snapshot is garbage once the scan ends. Only findings leave the scanner.
- **Egress:** the scanner talks only to the configured GitHub API host, its tarball host
  (`codeload.github.com`) and OSV. It uses the same IP guard as every probe. Go drops the
  `Authorization` header on the cross-host redirect, and the tarball URL carries its own
  short-lived token.

### 7. Dependencies: lockfiles first, OSV as the advisory source

- **Ecosystems this phase:** npm and PyPI.

  | Ecosystem | Files read |
  |---|---|
  | npm | `package-lock.json` (v1–v3) |
  | PyPI | `uv.lock`, `poetry.lock`, `Pipfile.lock`, and exact `==` pins in `requirements*.txt` |

- **Ranges are never guessed:** a manifest without a lockfile (`package.json`, a `>=` requirement)
  gives no finding. A guessed version would be a guessed finding.
- **Matching:** exact versions go to OSV (`api.osv.dev`, Google; it aggregates the GitHub
  Advisory Database, PyPA and others) through `/v1/querybatch`. Each advisory's details come from
  `/v1/vulns/{id}`.
- **What OSV learns:** package names and versions. No code, file content, repository name or
  user data is sent. The privacy text says so.
- **The fix is always given:** the scanner computes the lowest version that fixes every advisory
  of the package from the OSV ranges, using semver for npm and PEP 440 for PyPI. When no fixed
  version exists, a separate finding key says so and tells the user to replace or remove the
  package.

### 8. Severity reflects exposure, not the raw CVSS score

The catalog keeps one severity per finding key (same finding, same severity, same score), so the
tiers are separate keys:

| Key | Severity | When |
|---|---|---|
| `vulnerable_dependency_high` | high | runtime dependency, an advisory rated HIGH/CRITICAL (or a known-malicious release) |
| `vulnerable_dependency_medium` | medium | runtime dependency, MODERATE or unrated advisories |
| `vulnerable_dependency_low` | low | runtime dependency, only LOW advisories |
| `vulnerable_dev_dependency` | low | reachable only through development dependencies (not shipped) |
| `vulnerable_dependency_no_fix` | medium | runtime dependency with advisories that have no fixed version |

- **Nothing is critical.** GuardHub cannot prove a vulnerable function is reached. "critical"
  stays for exposures proven from the outside (e.g. an exposed `.env`).
- **The rating source:** the GitHub Advisory rating. Records without one use their CVSS v3 base
  score.

### 9. Secrets: curated rules, placeholder filtering, masked evidence

- **What is scanned:** the default branch's current files. Git history is a stated limit, a
  fast-follow.
- **Rules:** provider-specific patterns, gitleaks-style (AWS, GitHub, GitLab, Slack, Stripe,
  private keys, database URLs with a password, and others). They are checked for entropy and for
  placeholders (`EXAMPLE`, `xxxx`, `your_…`, `${VAR}`, repeated characters).
- **Ignored:** test, fixture and example paths. The prompt names fake keys in tests as false
  positives.
- **Generic keyword plus high-entropy assignments:** reported at medium only. Provider test-mode
  keys are low.
- **Evidence:** file, line, rule and the last four characters only. The line itself is never
  stored.
- **No liveness check:** GuardHub never "tries" a found key against the provider (§9.2: no active
  use of the customer's credentials).

### 10. Measured before it is switched on

- **The lab:** `test_corpus/repos/` holds lab repositories.
  - The GitHub API stand-in builds their tarballs. Planted secrets are generated when the lab
    starts, so no realistic secret is ever committed (our own CI secret scan and GitHub push
    protection stay meaningful).
  - The OSV stand-in replays answers **recorded from the real OSV API** (`test_corpus/osv/`).
- **Ground truth:** written by hand and checked with independent tools: osv-scanner for
  dependencies, gitleaks for the generated secrets. Never with our own scanner.
- **The gate:** the ADR-0004 gate. Both modules ship disabled.

## Consequences

- Founder setup: create the GitHub App (settings in `ops/runbooks/production.md` §9) and put its
  private key and client secret on the server. Until then the GitHub section says "not
  configured" and nothing else changes.
- GitHub and OSV become third parties of repo scanning. The privacy text names both.
- Not in this phase:
  - yarn/pnpm lockfiles, Go and Composer;
  - git-history secret scanning;
  - reachability analysis;
  - webhooks, and therefore push-triggered scans;
  - organisation and team sharing of an installation.

## Alternatives considered

- **OAuth app with the `repo` scope.** Rejected: write access, and every repository.
- **Storing the installation token encrypted.** Unnecessary: tokens are minted per scan and
  revoked after it.
- **The scanner holding the App private key.** Rejected: the scanner talks to the internet all day
  and should never be able to mint tokens for every customer.
- **Cloning with git into a temp dir.** Rejected: the code would touch disk, and git would need
  credentials on the command line.
- **A local OSV mirror.** Correct, and nothing leaves GuardHub, but it means a large, constantly
  updated dataset to run. A possible later step behind the same `SCANNER_OSV_URL` seam.
