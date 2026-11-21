"""Phase 2 check modules (second batch), registered DISABLED (§8.3, §12.4).

A module ships off. Switching it on in the admin is refused until the validation lab has
measured the check and it meets the accuracy gate (packages/shared/accuracy.json,
guardhub_api/modules/accuracy.py). EXPAND-ONLY: the previous release ignores unknown, disabled
modules (it only runs enabled ones it knows).

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-22
"""

from __future__ import annotations

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None

MODULES = [
    ("dns_email", "E-mail spoofing protection & DNS", "dns"),
]


def upgrade() -> None:
    for key, name, category in MODULES:
        op.execute(
            f"INSERT INTO modules (key, name, category, enabled_global) VALUES ('{key}', '{name}', '{category}', false) "
            "ON CONFLICT (key) DO NOTHING"
        )


def downgrade() -> None:
    keys = ", ".join(f"'{k}'" for k, _, _ in MODULES)
    op.execute(f"DELETE FROM modules WHERE key IN ({keys})")
