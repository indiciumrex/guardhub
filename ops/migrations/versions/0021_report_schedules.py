"""Scheduled admin reports (Admin Panel, Prompt 2 §3).

report_schedules: a weekly and a monthly platform summary e-mailed to the admins (counts and a
link only). Seeded switched off.

Admin/system only (RLS). EXPAND-ONLY: the previous release ignores the new table.

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-26
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    """CREATE TABLE report_schedules (
        frequency text PRIMARY KEY CHECK (frequency IN ('weekly', 'monthly')),
        enabled boolean NOT NULL DEFAULT false,
        last_sent_at timestamptz,
        updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
        updated_at timestamptz NOT NULL DEFAULT now()
    )""",
    "INSERT INTO report_schedules (frequency) VALUES ('weekly'), ('monthly')",
    "ALTER TABLE report_schedules ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY report_schedules_admin ON report_schedules FOR ALL
       USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
]

DOWNGRADE = ["DROP TABLE IF EXISTS report_schedules"]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)
    op.execute(f"GRANT SELECT, UPDATE ON report_schedules TO {_app_role()}")


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
