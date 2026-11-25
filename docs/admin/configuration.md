# Admin configuration & feature flags

Admin → Configuration (`/admin/config`, API `GET/PUT/POST /api/v1/admin/config…`, admin only).

## What can be changed

A fixed, typed list in `apps/api/guardhub_api/platform/registry.py`. Each tunable has hard
bounds and a default: the environment value or today's constant. With no overrides stored,
GuardHub behaves exactly as before.

| Group | Settings |
|---|---|
| Maintenance | `maintenance.enabled`, `maintenance.message` (max 280 characters) |
| Feature flags | `flags.public_scan`, `flags.registration`, `flags.scheduled_scans` |
| Scans | `scan.deadline_seconds` (30 to 300) |
| Concurrency | `scheduler.batch` (1 to 100), `scheduler.max_inflight` (1 to 50) |
| Rate limits (per hour) | challenges per address, scans without an account per address and per site, manual re-scans per project, sign-ups per address |

- **Maintenance mode** pauses every new passive scan (public, project, re-scan, scheduled,
  trusted domain) with `503 maintenance`, and shows a banner on the public site. Scans already
  running finish.
- **Owner active tests** do not depend on maintenance mode. They answer only to their own four
  locks and the kill switch.
- **Storage:** values live in `platform_settings` (migration 0019, admin/system RLS).
- **Propagation:** each process caches values for 5 seconds.
- **History:** every change is audited (`config.changed`, `config.reset`, `config.reverted`) with
  old value, new value and reason. That audit trail is the change history. A revert is a new
  change and is validated again.
- **Stuck-scan reaper:** it waits for the longest possible deadline (300 s plus grace), so lowering
  the deadline never fails a running scan early.

## What can never be changed here

These are security controls and stay in code and in the environment file:
- the four active-testing locks (founder approval, scanner switch, module switches, kill switch);
- ownership proof (§9.2) and its timeouts;
- sign-in, 2FA and session limits;
- secrets.

Two tests enforce it (`tests/test_platform_registry.py`):
- **Key names:** no registry key may contain a security word (`active`, `kill`, `owner`, `verif`,
  `login`, `secret` and others).
- **Imports:** the active-testing, ownership, accuracy-gate and auth code may never import
  `guardhub_api.platform`.

The environment panel is read-only. A secret is shown only as "configured" or "not set". A
non-secret value is shown only when it is on an explicit allowlist; everything else is "set
(hidden)".

Retries are not configurable: the API has none to tune, and the scanner's retry policy is part
of its request budget (ADR-0008).
