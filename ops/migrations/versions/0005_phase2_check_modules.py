"""Phase 2 check modules, registered DISABLED (§8.3, §12.4).

A module ships off. Switching it on in the admin is refused until the validation lab has
measured the check and it meets the accuracy gate (packages/shared/accuracy.json,
guardhub_api/modules/accuracy.py). EXPAND-ONLY: the previous release ignores unknown, disabled
modules (it only runs enabled ones it knows).

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-22
"""

from __future__ import annotations

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

MODULES = [
    ("tls_config", "TLS configuration", "transport"),
    ("http_hardening", "Browser policies (CORS, CSP quality, framing, referrer)", "hardening"),
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
