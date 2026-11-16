"""Roll out the six MVP checks (§8.3: modules ship disabled, then get enabled once tested).

Each of these checks has positive and negative tests and a docs/checks/<id>.md page, so they
are enabled globally here. Admins can switch any of them off from the admin panel.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-16
"""

from __future__ import annotations

from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

MVP_CHECKS = ("exposed_env", "security_headers", "tls_cert", "open_admin", "default_creds", "info_leak")


def upgrade() -> None:
    keys = ", ".join(f"'{k}'" for k in MVP_CHECKS)
    op.execute(f"UPDATE modules SET enabled_global = true, rolled_out_at = now() WHERE key IN ({keys})")


def downgrade() -> None:
    keys = ", ".join(f"'{k}'" for k in MVP_CHECKS)
    op.execute(f"UPDATE modules SET enabled_global = false, rolled_out_at = NULL WHERE key IN ({keys})")
