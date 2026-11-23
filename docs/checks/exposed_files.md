# Check `exposed_files` — forgotten files a web server hands to anyone

- **Code:** `apps/scanner/internal/checks/exposed_files.go` · tests: `exposed_files_test.go`
- **i18n:** `checks.json` → `exposed_files` (en, tr; the other locales are in the translation queue, §7.5)
- **Module:** ships disabled (migration 0012)
- **Accuracy:** [`docs/accuracy/exposed_files.md`](../accuracy/exposed_files.md) · **Decision record:** [ADR-0007](../adr/0007-phase4a-depth-methodology.md)

## What it detects

| Finding key | Severity | Params | When |
|---|---|---|---|
| `database_dump_exposed` | critical | `path` | an SQL dump **with data rows** (`INSERT INTO`, or `COPY … FROM stdin`) after a dump header or `CREATE TABLE`, plain or gzip-compressed |
| `source_backup_exposed` | high | `path` | a backup copy of PHP source whose body starts with `<?php` (served as text, not run) |
| `archive_backup_exposed` | high | `path` | ZIP or gzip magic bytes at a backup-archive path |
| `ds_store_exposed` | low | `path` | the `.DS_Store` signature (`\x00\x00\x00\x01Bud1`) |
| `source_map_exposed` | low | `path`, `source_count` | a same-origin version 3 source map of one of the home page's first 3 same-origin scripts, embedding original source (`sourcesContent`) |
| `default_page_exposed` | info | `server` | the home page is the stock welcome page of nginx, Apache (Ubuntu, Debian, RHEL family, plain httpd), IIS or Caddy |

**Severity (ADR-0007 rubric):**

- **critical:** a dump with data is "readable data", the rubric's critical case. Schema-only dumps
  are not reported.
- **high:**
  - Source backups usually carry configuration secrets (wp-config.php: database password, keys).
  - Site archives usually contain the whole site.
  - Both are directly usable by an outsider. GuardHub does not open archives, so it does not claim
    "critical".
- **low:** `.DS_Store` reveals file names, and source maps reveal front-end source. Both help an
  attacker, but neither exposes data.
- **info:** a default page is a configuration smell, not a weakness.

## Paths (fixed list, no brute force, no wordlists)

- **Dumps:**
  - `/backup.sql`, `/dump.sql`, `/db.sql`, `/database.sql`;
  - `/backup.sql.gz`, `/db.sql.gz`.
- **Source backups:**
  - `/wp-config.php.bak`, `/wp-config.php~`, `/wp-config.php.save`, `/wp-config.php.old`;
  - `/config.php.bak`;
  - `/index.php.bak`, `/index.php~`.
- **Archives:**
  - `/backup.zip`, `/backup.tar.gz`;
  - `/site.zip`, `/www.zip`.
- **macOS:** `/.DS_Store`.
- **Also read:** `/`, which is shared with other checks, and up to 3 scripts and their maps.

At most 20 requests per scan were measured in the lab. Bodies are read up to the probe's 256 KiB cap.

## How it works

Every hit is confirmed by the **content**, never by the status code alone. It must be HTTP 200,
not a cross-host redirect, and not byte-identical to the site's answer for a path that cannot
exist (soft-404 baseline shared with `exposed_env`).

Evidence never holds file contents:

- **dumps:** the table names and the number of INSERT lines;
- **PHP:** the names of `define()`d constants, never their values;
- **archives:** the signature and the size;
- **source maps:** the source file names.

## Not reported (false-positive discipline)

- **Schema-only dumps** (no data), and gzip files at dump paths that do not decompress to a dump.
- **A `.php.bak` that the server runs.** Its output is not source.
- **Source maps without `sourcesContent`.** File names alone are not reported. Neither are maps on
  another host and inline `data:` maps.
- **Anything a catch-all (single-page app) returns for every path.**
- **`.env`, `.git`, AWS credentials and directory listings.** These stay with `exposed_env` and
  `info_leak`.

## Validation

**Lab targets** (`ef-*`, `nginx/ef.conf`): `clean`'s headers and TLS, with content generated at lab
start by `test_corpus/ef-init.sh`.

- **Generated at start, not committed:** `.gitignore` excludes `.DS_Store`, and dumps and archives
  are binary.
- **The default page is genuine:** `ef-default` serves the nginx image's own stock page.
- **Negatives:**
  - `ef-schema`: a schema-only dump;
  - `ef-phprun`: an executed `.php.bak`;
  - `ef-mapnames`: a map without sources;
  - `clean`.

**Independent truth:** `test_corpus/oracles/files/oracle_files.py`, run by `oracles/headers/run.sh`
in CI's `header-truth` job on every site target (third-party apps one at a time):

- **Fetching:** curl.
- **File types:** libmagic (`file`): "PHP script", "gzip compressed data", "Zip archive data",
  "Apple Desktop Services Store".
- **Dumps:** a dump header plus data rows, after zcat.
- **Source maps:** found with Python's HTML parser on the home page, then the map's JSON.

`compare.py` fails the job on any manifest mismatch.
