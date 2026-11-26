"""Why a check could not finish (final prompt, item 4, 2026-11-26).

scans.check_errors keeps, per failed check, the scanner's reason code (budget_exceeded,
target_unreachable, timeout, internal, ...). Until now only failed_checks was kept, so a check
that stopped safely (the per-scan request budget, the target-stress breaker) could not be told
apart from a bug. Additive only: a new column with an empty default; no row changes.

Revision ID: 0030
Revises: 0029
Create Date: 2026-11-26
"""

from __future__ import annotations

from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS check_errors jsonb NOT NULL DEFAULT '{}'::jsonb")


def downgrade() -> None:
    op.execute("ALTER TABLE scans DROP COLUMN IF EXISTS check_errors")
