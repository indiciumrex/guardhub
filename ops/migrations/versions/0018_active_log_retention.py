"""Active request log retention: 30 days (founder decision 2026-11-25; ADR-0008 §7).

active_request_log stays append-only for everyone: no UPDATE, no TRUNCATE, and the app role
still has no DELETE grant. The one exception is the retention purge:
`active_request_log_purge()` (SECURITY DEFINER, no arguments) deletes the rows recorded more
than 30 days ago and returns how many. The trigger lets a DELETE through only inside that
function (a transaction-local flag it sets) and only for a row older than 30 days, so neither
a caller nor the flag alone can remove a younger row. The window is fixed here, not passed in.

EXPAND-ONLY: the previous release never calls the function; the trigger refuses what it refused.

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-25
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    """CREATE OR REPLACE FUNCTION active_request_log_immutable() RETURNS trigger LANGUAGE plpgsql AS
       $$ BEGIN
            IF TG_OP = 'DELETE'
               AND current_setting('guardhub.active_log_purge', true) = 'on'
               AND OLD.recorded_at < now() - interval '30 days' THEN
              RETURN OLD;
            END IF;
            RAISE EXCEPTION 'active_request_log is append-only';
          END $$""",
    """CREATE FUNCTION active_request_log_purge() RETURNS bigint
       LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS
       $$ DECLARE n bigint;
          BEGIN
            PERFORM set_config('guardhub.active_log_purge', 'on', true);
            DELETE FROM active_request_log WHERE recorded_at < now() - interval '30 days';
            GET DIAGNOSTICS n = ROW_COUNT;
            PERFORM set_config('guardhub.active_log_purge', 'off', true);
            RETURN n;
          END $$""",
    "REVOKE ALL ON FUNCTION active_request_log_purge() FROM PUBLIC",
    "CREATE INDEX active_request_log_recorded_idx ON active_request_log (recorded_at)",
]

DOWNGRADE = [
    "DROP INDEX IF EXISTS active_request_log_recorded_idx",
    "DROP FUNCTION IF EXISTS active_request_log_purge()",
    """CREATE OR REPLACE FUNCTION active_request_log_immutable() RETURNS trigger LANGUAGE plpgsql AS
       $$ BEGIN RAISE EXCEPTION 'active_request_log is append-only'; END $$""",
]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)
    op.execute(f"GRANT EXECUTE ON FUNCTION active_request_log_purge() TO {_app_role()}")


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
