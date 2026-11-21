# Check `dependency_vulns` — known vulnerabilities in a repository's dependencies

- **Code:** `apps/scanner/internal/checks/dependency_vulns.go`, `internal/deps/` (lockfiles, versions, OSV, advisory logic) · tests: `dependency_vulns_test.go`, `internal/deps/*_test.go`
- **Target:** a connected GitHub repository (check-ids.json `"target": "repo"`) · **i18n:** `checks.json` → `dependency_vulns` · **Module:** ships disabled (migration 0008)
- **Accuracy:** [`docs/accuracy/dependency_vulns.md`](../accuracy/dependency_vulns.md) · **Decision record:** [ADR-0006](../adr/0006-github-repo-scanning.md)

## What it detects

One finding per (lockfile, package): the package version GuardHub read, every advisory that
affects it, and the lowest version that fixes all of them.

| Finding key | Severity | When |
|---|---|---|
| `vulnerable_dependency_high` | high | a runtime dependency with an advisory rated HIGH or CRITICAL, or a known-malicious release (OpenSSF `MAL-` record, dev or not) |
| `vulnerable_dependency_medium` | medium | a runtime dependency whose worst advisory is MODERATE, or has no rating |
| `vulnerable_dependency_low` | low | a runtime dependency with only LOW advisories |
| `vulnerable_dev_dependency` | low | reachable only through development dependencies (not shipped) |
| `vulnerable_dependency_no_fix` | medium | a runtime dependency none of whose advisories has a fixed version |

Params of every key: `package`, `version`, `ecosystem`, `manifest`, `advisories` (display ids:
the CVE alias, else the GHSA id, else the OSV id; at most 8 shown plus "+N"), and
`fixed_version`, except on `vulnerable_dependency_no_fix`. A development dependency with no
fixed release gets `fixed_version` "-"; its text explains it.

**Severity reflects exposure, not the raw CVSS score:**

- **Nothing is critical.** GuardHub cannot prove the vulnerable function is reached; "critical"
  stays for exposures proven from outside.
- **Rating source.** An issue is a group of records that alias each other (e.g. GHSA + PYSEC +
  CVE). It is rated by the GitHub Advisory rating when any record of the group has one. Only
  when none does, the highest CVSS v3 base score among its vectors is used.
- **The lab caught this rule.** For CVE-2024-56326 (jinja2), GitHub rates it MODERATE while the
  PYSEC alias's local-attack vector scores 7.8. Taking the maximum would have said "high".

## What it reads (exact versions only)

| Ecosystem | Files | Development dependency = |
|---|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json` (lockfile v1, v2, v3) | `"dev": true` (a package that is both dev and runtime counts as runtime) |
| PyPI | `uv.lock` | reachable only from a workspace member's dev-dependency groups (optional extras count as runtime) |
| PyPI | `poetry.lock` | `category = "dev"` (lock format 1.x); format 2.x has no categories, so everything counts as runtime, the conservative choice |
| PyPI | `Pipfile.lock` | the `develop` section |
| PyPI | `requirements*.txt`, `requirements/*.txt` (`==` and `===` pins only) | the file name says dev/test/lint/docs/ci (`requirements-dev.txt`, `requirements/test.txt`) |

**Never guessed:**

- a version range (`package.json` without a lockfile, `flask>=1.0`);
- URL, git and path dependencies;
- workspace links.

A guessed version would be a guessed finding. `-r other.txt` includes are not followed: the
included file is read on its own.

**Skipped:** vendored directories (`node_modules/`, `vendor/`, `.venv/`, …).

## How it works

1. **Snapshot.** The scanner reads the default branch into memory: one tarball, at most
   48 MiB kept, lockfiles up to 16 MiB each (ADR-0006 §6). Nothing touches disk.
2. **Match.** Every exact `(ecosystem, name, version)` goes to OSV's `/v1/querybatch`
   (`SCANNER_OSV_URL`, default `https://api.osv.dev`). Each returned advisory's record comes
   from `/v1/vulns/{id}`, at most 400 per scan. Only package names and versions leave GuardHub.
3. **Assess.**
   - Withdrawn records are ignored.
   - Records that alias each other are one issue.
   - **The fix for an issue** is the `fixed` event that closes the OSV range containing the
     version (events are sorted by version first). If OSV matched the version through its
     explicit list instead, it is the lowest `fixed` above the version.
   - **Version order:** SemVer 2.0 for npm and PEP 440 for PyPI, both implemented and
     unit-tested in `internal/deps/version.go`.
   - **The package's `fixed_version`** is the highest of its issues' fixes: the lowest version
     that fixes them all.
4. **Report.**
   - **Evidence** (kind `dependency`, location
     `https://github.com/<repo>/blob/HEAD/<manifest>#<package>`) lists each issue with its
     rating and fix, plus the commit scanned.
   - **The location has no commit and no version**, so a partial upgrade is still the same
     finding in scan diffs.

## Incomplete scans are said so

The check reports its findings and also fails (shown as "could not fully run") with:

- `repo_too_large`: a snapshot cap was hit, or more than 400 advisories matched;
- `manifest_unreadable`: a lockfile did not parse (the others were still read);
- `advisory_db_unavailable`: OSV could not be asked. Then nothing is reported, never "clean".

## False-positive and false-negative risks

- **False positives** would need OSV to list the exact version, which is OSV's data, not a
  guess. The lab's negatives are:
  - clean packages;
  - ranges without lockfiles;
  - committed `node_modules`;
  - a vendored requirements file;
  - a repository with no lockfile.
- **Severity disagreements** count as both a false positive and a false negative in the lab
  (the key is part of the match), as do wrong `fixed_version` values (manifests pin them).
- **False negatives:**
  - yarn and pnpm lockfiles, Go, Composer and other ecosystems (not read yet);
  - ranges;
  - vendored code;
  - more than the caps;
  - vulnerabilities OSV does not know.
- **Reachability:** GuardHub does not analyse whether the vulnerable code is called. That is
  why nothing is critical, and why development dependencies are low.
