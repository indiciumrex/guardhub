# `exposed_files` accuracy

Lab source revision `709c7f0ecbd3`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 8 | 0 | 0 | 0 | 0 | 110 | 102 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `archive_backup_exposed` | 1 | 0 | 0 |
| `database_dump_exposed` | 2 | 0 | 0 |
| `default_page_exposed` | 1 | 0 | 0 |
| `ds_store_exposed` | 1 | 0 | 0 |
| `source_backup_exposed` | 1 | 0 | 0 |
| `source_map_exposed` | 2 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (8)

- `ef-archive` / `archive_backup_exposed` at `https://ef-archive.lab.test/backup.tar.gz`: Files oracle (curl + libmagic, lab run 2026-11-23): /backup.tar.gz: libmagic 'gzip compressed data, from Unix'.
- `ef-default` / `default_page_exposed` at `https://ef-default.lab.test/`: Files oracle (curl + Python html.parser, lab run 2026-11-23): home page title 'Welcome to nginx!', the nginx image's own stock page (copied by ef-init.sh).
- `ef-dsstore` / `ds_store_exposed` at `https://ef-dsstore.lab.test/.DS_Store`: Files oracle (curl + libmagic, lab run 2026-11-23): /.DS_Store: libmagic 'Apple Desktop Services Store'.
- `ef-dump` / `database_dump_exposed` at `https://ef-dump.lab.test/backup.sql`: Files oracle (curl + libmagic, lab run 2026-11-23): /backup.sql: libmagic 'ASCII text', MySQL dump header and INSERT INTO data rows.
- `ef-dumpgz` / `database_dump_exposed` at `https://ef-dumpgz.lab.test/db.sql.gz`: Files oracle (curl + libmagic, lab run 2026-11-23): /db.sql.gz: libmagic 'gzip compressed data, max compression, from Unix'; decompressed: PostgreSQL dump header and COPY ... FROM stdin data rows.
- `ef-phpbak` / `source_backup_exposed` at `https://ef-phpbak.lab.test/wp-config.php.bak`: Files oracle (curl + libmagic, lab run 2026-11-23): /wp-config.php.bak: libmagic 'PHP script, ASCII text'.
- `ef-sourcemap` / `source_map_exposed` at `https://ef-sourcemap.lab.test/static/app.js.map`: Files oracle (curl + Python html.parser, lab run 2026-11-23): home page script /static/app.js -> /static/app.js.map: HTTP 200, version 3, 2 sources, 2 embedded (sourcesContent).
- `grafana` / `source_map_exposed` at `http://grafana.lab.test:3000/public/build/runtime.a83631aa5c22ce7c0887.js.map`: Files oracle (curl + Python html.parser, local run of the pinned image, 2026-11-23): / -> same-host redirect -> /login (200), whose script runtime.a83631aa5c22ce7c0887.js maps to this file: HTTP 200, version 3, 21 sources, 21 embedded (sourcesContent), served without authentication as Grafana ships. Missing from this manifest at first; CI's accuracy run 45116314006 surfaced it as a false positive.

