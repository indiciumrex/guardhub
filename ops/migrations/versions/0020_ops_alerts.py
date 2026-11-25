"""Operational alerts for admins (Admin Panel, Prompt 2 §2).

ops_alert_rules: one row per alert kind with its threshold, window, e-mail channel, mute and
escalation. Seeded with conservative defaults; in-app alerts are always recorded.
ops_alerts: the alert inbox. At most one unresolved alert per kind (partial unique index): the
evaluator updates it while the condition holds and resolves it when the condition clears.

Admin/system only (RLS). EXPAND-ONLY: the previous release ignores both tables.

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-26
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None

KINDS = "('critical_finding', 'scan_failures', 'worker_offline', 'api_errors')"


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    f"""CREATE TABLE ops_alert_rules (
        kind text PRIMARY KEY CHECK (kind IN {KINDS}),
        enabled boolean NOT NULL DEFAULT true,
        threshold integer NOT NULL CHECK (threshold BETWEEN 1 AND 1000),
        window_minutes integer NOT NULL CHECK (window_minutes BETWEEN 5 AND 1440),
        email boolean NOT NULL DEFAULT true,
        muted_until timestamptz,
        escalate_after_minutes integer CHECK (escalate_after_minutes BETWEEN 5 AND 1440),
        updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
        updated_at timestamptz NOT NULL DEFAULT now()
    )""",
    """INSERT INTO ops_alert_rules (kind, threshold, window_minutes, escalate_after_minutes) VALUES
        ('critical_finding', 1, 60, NULL),
        ('scan_failures', 5, 30, 60),
        ('worker_offline', 5, 5, 30),
        ('api_errors', 20, 15, 60)""",
    f"""CREATE TABLE ops_alerts (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        kind text NOT NULL CHECK (kind IN {KINDS}),
        status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
        value integer NOT NULL,
        threshold integer NOT NULL,
        detail jsonb NOT NULL DEFAULT '{{}}'::jsonb CHECK (octet_length(detail::text) <= 4096),
        opened_at timestamptz NOT NULL DEFAULT now(),
        last_seen_at timestamptz NOT NULL DEFAULT now(),
        acknowledged_at timestamptz,
        acknowledged_by uuid REFERENCES users(id) ON DELETE SET NULL,
        resolved_at timestamptz,
        resolved_by uuid REFERENCES users(id) ON DELETE SET NULL,
        emailed_at timestamptz,
        escalated_at timestamptz
    )""",
    "CREATE UNIQUE INDEX ops_alerts_one_unresolved ON ops_alerts (kind) WHERE status <> 'resolved'",
    "CREATE INDEX ops_alerts_opened_idx ON ops_alerts (opened_at DESC)",
    "ALTER TABLE ops_alert_rules ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE ops_alerts ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY ops_alert_rules_admin ON ops_alert_rules FOR ALL
       USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
    """CREATE POLICY ops_alerts_admin ON ops_alerts FOR ALL
       USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
]

DOWNGRADE = ["DROP TABLE IF EXISTS ops_alerts", "DROP TABLE IF EXISTS ops_alert_rules"]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)
    role = _app_role()
    op.execute(f"GRANT SELECT, UPDATE ON ops_alert_rules TO {role}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON ops_alerts TO {role}")


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
