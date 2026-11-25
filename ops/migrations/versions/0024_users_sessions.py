"""Users & sessions, simple (Admin Panel, Prompt 2 §5).

- users.disabled_at / disabled_by: a disabled account cannot sign in; disabling also revokes its
  sessions and stops its API keys. last_login_at: set when a full (2FA) session starts.
- admin_invites: a one-time link (hash stored, 72 h) that makes the signed-in account with
  exactly that e-mail, after two-factor sign-in, an admin. No full role matrix (RBAC deferred).

admin_invites: admin/system only (RLS). EXPAND-ONLY: new nullable columns; the previous release
ignores them and the new table.

Revision ID: 0024
Revises: 0023
Create Date: 2026-11-26
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0024"
down_revision = "0023"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    "ALTER TABLE users ADD COLUMN disabled_at timestamptz",
    "ALTER TABLE users ADD COLUMN disabled_by uuid REFERENCES users(id) ON DELETE SET NULL",
    "ALTER TABLE users ADD COLUMN last_login_at timestamptz",
    """CREATE TABLE admin_invites (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        email text NOT NULL CHECK (email = lower(email) AND length(email) <= 254),
        token_hash text NOT NULL UNIQUE CHECK (length(token_hash) = 64),
        invited_by uuid REFERENCES users(id) ON DELETE SET NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        expires_at timestamptz NOT NULL,
        accepted_at timestamptz,
        accepted_by uuid REFERENCES users(id) ON DELETE SET NULL,
        revoked_at timestamptz,
        CHECK (expires_at <= created_at + interval '73 hours')
    )""",
    "ALTER TABLE admin_invites ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY admin_invites_admin ON admin_invites FOR ALL
       USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
]

DOWNGRADE = [
    "DROP TABLE IF EXISTS admin_invites",
    "ALTER TABLE users DROP COLUMN IF EXISTS last_login_at",
    "ALTER TABLE users DROP COLUMN IF EXISTS disabled_by",
    "ALTER TABLE users DROP COLUMN IF EXISTS disabled_at",
]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON admin_invites TO {_app_role()}")


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
