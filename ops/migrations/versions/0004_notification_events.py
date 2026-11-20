"""Alert history for alerts that are not about a scan: "monitoring paused" and test messages.

EXPAND-ONLY (blue/green, ops/runbooks/production.md §2): a NEW table instead of a nullable
`notifications.scan_id`. The previous release reads `notifications` and requires a scan id per
row; it never reads this table, so it keeps working while this release migrates and after a
rollback.

- notification_events: one row per (event, channel), keyed by `dedupe_key` (the alert job's
  unique id), so a retried or duplicated job never sends twice (replaces the Redis marker the
  paused alert used). `kind` = 'monitoring_paused' | 'test'; tests are recorded so a user can
  see them, and the history filters them out by default.
- Same access rules as `notifications`: users READ their own rows, only 'system' writes.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-21
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    """CREATE TABLE notification_events (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        project_id uuid REFERENCES projects(id) ON DELETE CASCADE,
        kind text NOT NULL CHECK (kind IN ('monitoring_paused', 'test')),
        dedupe_key text NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 200),
        channel text NOT NULL CHECK (channel IN ('email', 'slack')),
        status text NOT NULL CHECK (status IN ('pending', 'sent', 'failed', 'skipped')),
        attempts integer NOT NULL DEFAULT 0,
        error text,
        created_at timestamptz NOT NULL DEFAULT now(),
        sent_at timestamptz,
        CHECK (kind <> 'monitoring_paused' OR project_id IS NOT NULL)
    )""",
    "CREATE UNIQUE INDEX notification_events_dedupe_key ON notification_events (dedupe_key, channel)",
    "CREATE INDEX notification_events_user_idx ON notification_events (user_id, created_at DESC)",
    "ALTER TABLE notification_events ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY notification_events_read ON notification_events FOR SELECT
       USING (user_id = app_user_id() OR app_is_privileged())""",
    """CREATE POLICY notification_events_write ON notification_events FOR ALL
       USING (app_role() = 'system') WITH CHECK (app_role() = 'system')""",
]


def upgrade() -> None:
    for stmt in [*UPGRADE, f"GRANT SELECT, INSERT, UPDATE ON notification_events TO {_app_role()}"]:
        op.execute(stmt)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS notification_events")
