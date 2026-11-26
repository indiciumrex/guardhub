"""Own profile and password change (profile prompt, item 1, 2026-11-26).

users.display_name: an optional name the account holder sets for themselves (shown in the panel
and the admin console; never used for authorisation).
users.password_changed_at: when the password was last changed through the signed-in flow
(current password + a current two-factor code). Audited; other sessions end at that moment.

No data is changed or deleted. The privileged-column guard (0025) is untouched: these columns are
the account holder's own.

Revision ID: 0028
Revises: 0027
Create Date: 2026-11-26
"""

from __future__ import annotations

from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE users ADD COLUMN display_name text "
        "CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 80)"
    )
    op.execute("ALTER TABLE users ADD COLUMN password_changed_at timestamptz")


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at")
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS display_name")
