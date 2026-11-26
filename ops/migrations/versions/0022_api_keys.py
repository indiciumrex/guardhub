"""API keys for integrations (Admin Panel, Prompt 2 §4).

api_keys: a key an admin creates for an integration. Only its keyed hash is stored (the key is
shown once). It has one or more read / trigger scopes, an expiry (at most 366 days) and can be
revoked. A key never authorises the admin API: it acts as its owner in the user role (RLS) on
the /integrations routes only, and a triggered scan still needs a fresh ownership proof (§9.2).

Admin/system only (RLS). EXPAND-ONLY: the previous release ignores the new table.

Revision ID: 0022
Revises: 0021
Create Date: 2026-11-26
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    """CREATE TABLE api_keys (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
        prefix text NOT NULL CHECK (length(prefix) = 12),
        key_hash text NOT NULL UNIQUE CHECK (length(key_hash) = 64),
        scopes text[] NOT NULL CHECK (
            cardinality(scopes) >= 1
            AND scopes <@ ARRAY['projects:read', 'scans:read', 'scans:trigger']::text[]
        ),
        expires_at timestamptz NOT NULL,
        created_at timestamptz NOT NULL DEFAULT now(),
        last_used_at timestamptz,
        revoked_at timestamptz,
        revoked_by uuid REFERENCES users(id) ON DELETE SET NULL,
        CHECK (expires_at <= created_at + interval '366 days')
    )""",
    "CREATE INDEX api_keys_user_idx ON api_keys (user_id)",
    "ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY api_keys_admin ON api_keys FOR ALL
       USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
]

DOWNGRADE = ["DROP TABLE IF EXISTS api_keys"]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON api_keys TO {_app_role()}")


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
