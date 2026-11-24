"""Admin control centre (§8.3): scan cancellation, module maintenance mode, finding triage.

- scans.status gains 'cancelled' (an admin stopped a queued or running scan). The scanner's later
  events for a cancelled scan are ignored by the API.
- modules.maintenance: a module kept out of new scans without being switched off (its flag and
  gate history stay as they are). Default false: nothing changes for existing modules.
- finding_triage: the admin's verdict on one finding group (fingerprint = the same finding across
  scans): verified, accepted (risk accepted), false_positive or resolved, with a note. Admin and
  system only; customers never see or change it. Every change is audited (finding.triage).

EXPAND-ONLY: the previous release never writes 'cancelled', ignores the new column and table.

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-25
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    "ALTER TABLE scans DROP CONSTRAINT scans_status_check",
    """ALTER TABLE scans ADD CONSTRAINT scans_status_check
       CHECK (status IN ('queued', 'running', 'done', 'failed', 'cancelled'))""",
    "ALTER TABLE modules ADD COLUMN maintenance boolean NOT NULL DEFAULT false",
    """CREATE TABLE finding_triage (
        fingerprint text PRIMARY KEY CHECK (length(fingerprint) <= 128),
        check_id text NOT NULL CHECK (length(check_id) <= 64),
        status text NOT NULL CHECK (status IN ('verified', 'accepted', 'false_positive', 'resolved')),
        note text NOT NULL DEFAULT '' CHECK (length(note) <= 500),
        updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
        updated_at timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX finding_triage_check_idx ON finding_triage (check_id, status)",
    "ALTER TABLE finding_triage ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY finding_triage_admin ON finding_triage FOR ALL
       USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
]

DOWNGRADE = [
    "DROP TABLE IF EXISTS finding_triage",
    "ALTER TABLE modules DROP COLUMN IF EXISTS maintenance",
    "UPDATE scans SET status = 'failed', error = 'cancelled' WHERE status = 'cancelled'",
    "ALTER TABLE scans DROP CONSTRAINT scans_status_check",
    """ALTER TABLE scans ADD CONSTRAINT scans_status_check
       CHECK (status IN ('queued', 'running', 'done', 'failed'))""",
]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON finding_triage TO {_app_role()}")


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
