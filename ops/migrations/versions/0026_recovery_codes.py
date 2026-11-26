"""Two-factor recovery codes (Admin Panel gaps, 2026-11-26).

recovery_codes: ten single-use codes per account, created when two-factor sign-in is first set
up (and on request, with a current code), shown once. Only a keyed hash (pepper) is stored. A
used code is kept with used_at so it can never be used again. A user reads only their own rows
(RLS); admins and the system read all.

Revision ID: 0026
Revises: 0025
Create Date: 2026-11-26
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    """CREATE TABLE recovery_codes (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        code_hash text NOT NULL UNIQUE CHECK (length(code_hash) = 64),
        created_at timestamptz NOT NULL DEFAULT now(),
        used_at timestamptz
    )""",
    "CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id)",
    "ALTER TABLE recovery_codes ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY recovery_codes_access ON recovery_codes
       USING (user_id = app_user_id() OR app_is_privileged())
       WITH CHECK (user_id = app_user_id() OR app_is_privileged())""",
]

DOWNGRADE = ["DROP TABLE IF EXISTS recovery_codes"]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON recovery_codes TO {_app_role()}")


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
