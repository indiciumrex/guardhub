"""Phase 4A depth module exposed_files, registered DISABLED (ADR-0007 §1).

Same rule as 0005-0011: a module ships off, and switching it on in the admin is refused until
the validation lab has measured the check and it meets the accuracy gate
(packages/shared/accuracy.json). EXPAND-ONLY: the previous release ignores unknown, disabled
modules.

Revision ID: 0012
Revises: 0011
Create Date: 2026-11-23
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

MODULES = [
    ("exposed_files", "Forgotten files (database dumps, source backups, archives, .DS_Store, source maps, default pages)", "exposure"),
]


def upgrade() -> None:
    insert = sa.text(
        "INSERT INTO modules (key, name, category, enabled_global) "
        "VALUES (:key, :name, :category, false) ON CONFLICT (key) DO NOTHING"
    )
    for key, name, category in MODULES:
        op.get_bind().execute(insert, {"key": key, "name": name, "category": category})


def downgrade() -> None:
    delete = sa.text("DELETE FROM modules WHERE key = :key")
    for key, _, _ in MODULES:
        op.get_bind().execute(delete, {"key": key})
