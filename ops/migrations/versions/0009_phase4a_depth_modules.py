"""Phase 4A depth modules tls_depth and header_quality, registered DISABLED (ADR-0007 §1).

Same rule as 0005-0008: a module ships off, and switching it on in the admin is refused until
the validation lab has measured the check and it meets the accuracy gate
(packages/shared/accuracy.json). EXPAND-ONLY: the previous release ignores unknown, disabled
modules.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

MODULES = [
    ("tls_depth", "Certificate depth (signatures, lifetime, CT, OCSP, HSTS preload)", "transport"),
    ("header_quality", "Browser-policy header quality (CSP, Permissions-Policy, COOP, caching)", "hardening"),
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
