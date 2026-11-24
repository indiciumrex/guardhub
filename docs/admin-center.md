# Admin control centre (GUARDHUB_STANDARDS §8.3)

The admin area at `/admin` (role `admin` + full MFA; everyone else gets 404, in the web layout
and on every API route). The boundary lives in the backend: every `/api/v1/admin/*` route
depends on `AdminSession` (role re-read from the database), reads under the `admin` RLS context,
and every change is written to the append-only audit log.

Deliberately not here yet (deferred): billing, subscriptions and MRR, a multi-role RBAC matrix,
threat-intel, correlation, anomaly, SLA, policy or event engines. Admin and customer are the only
roles.

| Section | Page | API |
|---|---|---|
| Overview | `/admin` | `GET /admin/overview`, `GET /admin/ai` |
| Module Center | `/admin/modules` | `GET /admin/modules`, `GET /admin/modules/stats`, `PATCH /admin/modules/{key}`, `PATCH /admin/modules/{key}/config`, `GET /admin/modules/{key}/changelog` |
| Scan orchestration | `/admin/scans`, `/admin/scans/{id}` | `GET /admin/orchestration`, `GET /admin/scans/detailed?stage=`, `GET /admin/scans/{id}`, `POST /admin/scans/{id}/cancel`, `POST /admin/scans/{id}/rerun`, `GET /admin/scans/{id}/risk`, `GET`/`POST /admin/active/kill` |
| Findings & risk | `/admin/findings` | `GET /admin/findings?severity=&triage=&check_id=`, `PUT /admin/findings/{fingerprint}/triage` |
| Audit & monitoring | `/admin/audit` | `GET /admin/audit?action=&actor=&target=`, `GET /admin/monitoring` |
| Users | `/admin/users` | `GET /admin/users` |
| Trusted domains | `/admin/trusted-domains` | ADR-0003 |

## Overview

- **Scans** by lifecycle: queued, running, completed, failed, timed out (`failed` + `timeout`) and
  cancelled, plus the last 24 hours.
- **Open findings** by severity: the latest completed scan of each target.
- **Module success rates:** of the last 7 days' completed scans that included a check, how many
  could run it to the end.
- **Health:** database, Redis and scanner liveness, plus the queue.
- **Recent admin actions** (audit log) and **recent errors.**

## Module Center

- **Each module shows:** id, name, category, stage, status, its lab gate, production numbers,
  switch, settings and change history.
  - **Stage:** `beta` for the Phase 4B active checks.
  - **Status:** Active, Maintenance or Disabled.
- **The gate:**
  - **Gate L** (passive checks) is read from `docs/accuracy/scorecard.json`.
  - **Gate M** (active checks) is read from `docs/accuracy-active/scorecard.json`.
  - Both are CI-generated and copied into the API image.
  - Shown per check: precision, recall, lab false-positive rate (`fp / (tp + fp)`), counts and
    the measured git revision.
- **Production:**
  - the 7-day success rate;
  - how many distinct findings admins marked as false positives.
- **"No gate, no ON" is shown, not only enforced.** A module that may not be switched on shows a
  lock and the reason instead of a switch. The API refuses the same switch with the same rule
  (`modules/registry.py`):
  - `active_testing_not_approved`;
  - `module_not_measured`;
  - `gate_not_met`.
- **Settings:**
  - **Maintenance** keeps a module out of new scans without switching it off.
  - **Minimum plan.**
  - Both are audited as `module.config`, with before and after values.

## Scan orchestration

- **Lifecycle filters, plus cancel and run again.**
  - **Cancel** sets `gh:scan:cancel:<id>`: the scanner skips the job if it hasn't started it. It
    also sets the scan's active kill key, marks the scan `cancelled`, and the API ignores the
    scan's later events. Audited as `scan.cancel`.
  - **Run again** starts a new scan of the same project through the owner's rules: ownership is
    re-proven when stale, and only one active scan runs per project. Audited as `scan.rerun`.
- **Ownership proof** per scan (§9.2): project proof or one-time proof, with method and time.
- **Active testing (Phase 4B), shown on or off:**
  - **On** only when all of these hold: the founder's API approval, a scanner reporting its
    switch on, at least one active module on, and the kill switch released.
  - **The kill switch:** stop all active tests, or one scan by id.
- **Limits:**
  - **Passive scans:** what each scanner reports at `gh:scanner:info:<consumer>`, refreshed
    every 30 s with a 90 s TTL.
  - **Active tests:** fixed limits, compiled into the scanner.
- **Backpressure:** the queue's lag (not yet read), pending (in progress) and readers.
- **Risk score explained:** `score = max(0, 100 − Σ weight[severity])`, with each finding's points.

## Findings & risk

- **Grouping:** findings are grouped by fingerprint, so the same finding across scans appears
  once, with its occurrence count and first and last seen.
- **Standard ids:**
  - **CWE.**
  - **CVSS v3.1:** an *indicative* base vector for the typical case of the finding kind. It is
    labelled as such, and GuardHub's own severity still decides the score.
  - **CVE/GHSA ids:** where the scanner reported them.
  - Source: `findings/taxonomy.py`.
- **Triage:** new, verified, accepted risk, false positive, resolved.
  - Stored per fingerprint in `finding_triage` (admin and system only, RLS).
  - Audited as `finding.triage`.
  - Customers never see it, and it never changes their findings.

## Audit & monitoring

- **The audit log:**
  - Shows actor (and their e-mail), time, action, target, before and after (the row's metadata),
    and the client's **keyed IP hash**.
  - IPs are never stored (`common/audit.py`; the API middleware sets the hash per request).
  - Filters: action prefix, actor, target.
- **Monitoring:**
  - Live health, module health (error rates), queue and scanners.
  - Recent errors: failed scans and degraded modules from GuardHub's own records.
- **Sentry issues (optional):**
  - Shown only with a read-only token (`SENTRY_API_TOKEN`, `SENTRY_ORG`, `SENTRY_PROJECT`).
  - They are reached through the egress proxy (`SENTRY_API_PROXY`, with `sentry.io` on its
    allowlist): the API container has no internet route of its own.
  - Until then the panel says so.
