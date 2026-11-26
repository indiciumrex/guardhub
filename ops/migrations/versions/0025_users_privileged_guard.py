"""Database guard for the privileged user columns (Admin Panel gaps, 2026-11-26).

`users.role`, `users.disabled_at` and `users.disabled_by` may change only in an admin or system
context (`app_is_privileged()`), or from a maintenance connection that is not the application
role (the database owner running migrations or a manual fix). A customer session, even with a
bug in the API, can no longer make itself an admin or lift its own suspension. An INSERT from a
non-privileged context must create a plain, enabled customer.

The operator CLI (`python -m guardhub_api.admin.bootstrap promote`) runs in the system context,
so it keeps working; so do admin invitations (system) and the admin console (admin).

Revision ID: 0025
Revises: 0024
Create Date: 2026-11-26
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


def upgrade() -> None:
    role = _app_role()
    op.execute(
        f"""CREATE FUNCTION users_guard_privileged_columns() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF app_is_privileged() OR current_user <> '{role}' THEN
                RETURN NEW;
            END IF;
            IF TG_OP = 'INSERT' THEN
                IF NEW.role <> 'user' OR NEW.disabled_at IS NOT NULL OR NEW.disabled_by IS NOT NULL THEN
                    RAISE EXCEPTION 'users: only a plain customer may be created here'
                        USING ERRCODE = '42501';
                END IF;
            ELSIF NEW.role IS DISTINCT FROM OLD.role
               OR NEW.disabled_at IS DISTINCT FROM OLD.disabled_at
               OR NEW.disabled_by IS DISTINCT FROM OLD.disabled_by THEN
                RAISE EXCEPTION 'users: role and disabled state change only in an admin or system context'
                    USING ERRCODE = '42501';
            END IF;
            RETURN NEW;
        END
        $$"""
    )
    op.execute(
        """CREATE TRIGGER users_guard_privileged_columns
        BEFORE INSERT OR UPDATE ON users
        FOR EACH ROW EXECUTE FUNCTION users_guard_privileged_columns()"""
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS users_guard_privileged_columns ON users")
    op.execute("DROP FUNCTION IF EXISTS users_guard_privileged_columns()")
