# `open_admin` accuracy

Lab source revision `69ee5204062c+wip`. Verdict: **meets the gate**.

| Precision | Recall | Recall (all) | TP | FP | FN | FN outside | Tolerated | Targets | Clean targets | Errors |
|---|---|---|---|---|---|---|---|---|---|---|
| 100.0% | 100.0% | 100.0% | 3 | 0 | 0 | 0 | 0 | 44 | 41 | 0 |

## By finding

| Finding key | TP | FP | FN |
|---|---|---|---|
| `db_admin_exposed` | 1 | 0 | 0 |
| `server_status_exposed` | 2 | 0 | 0 |

## False positives (0)

None.

## False negatives (0)

None.

## True positives (3)

- `grafana` / `server_status_exposed` at `http://grafana.lab.test:3000/metrics`: /metrics serves Grafana's Prometheus metrics (text/plain, "# HELP"/"# TYPE") without authentication, Grafana's default. Missing from this manifest at first; the lab run surfaced it and curl confirmed it (2026-11-21).
- `juice-shop` / `server_status_exposed` at `http://juice-shop.lab.test:3000/metrics`: /metrics serves Prometheus metrics without authentication (documented challenge).
- `phpmyadmin` / `db_admin_exposed` at `http://phpmyadmin.lab.test/`: phpMyAdmin's login is reachable from the network at /.

