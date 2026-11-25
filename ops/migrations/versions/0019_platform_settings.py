"""Admin configuration (Admin Panel, Prompt 2 §1): runtime platform settings and feature flags.

platform_settings holds the admin's overrides of a fixed, typed list of tunables
(guardhub_api/platform/registry.py): scan deadline, scheduler batch and concurrency, public
rate limits, feature flags and maintenance mode. A key without a row uses its default (the
environment value), so an empty table changes nothing. Every change is audited (config.*), and
the audit log is the change history the admin can revert from.

Nothing here can reach the active-testing locks, the kill switch or ownership proof (§9.2): those
keys do not exist in the registry, and the API rejects any key that is not in it.

Admin/system only (RLS). EXPAND-ONLY: the previous release ignores the new table.

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-26
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    """CREATE TABLE platform_settings (
        key text PRIMARY KEY CHECK (key ~ '^[a-z_]+(\.[a-z_]+)+$' AND length(key) <= 64),
        value jsonb NOT NULL CHECK (octet_length(value::text) <= 1024),
        updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
        updated_at timestamptz NOT NULL DEFAULT now()
    )""",
    "ALTER TABLE platform_settings ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY platform_settings_admin ON platform_settings FOR ALL
       USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
]

DOWNGRADE = ["DROP TABLE IF EXISTS platform_settings"]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON platform_settings TO {_app_role()}")


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
