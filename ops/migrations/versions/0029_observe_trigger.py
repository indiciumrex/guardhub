"""Observe-only scans (profile prompt, item 3, 2026-11-26).

scans.trigger gains the value 'observe': a passive scan a super-admin started WITHOUT an
ownership proof, limited to observe-only checks, with the authorisation statement in the audit
log. It has no project and no public token, so scans_check (project OR public token) gains a
third case: trigger 'observe' with an owning user. Constraints are widened only; no row changes.

Revision ID: 0029
Revises: 0028
Create Date: 2026-11-26
"""

from __future__ import annotations

from alembic import op

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_check")
    op.execute(
        "ALTER TABLE scans ADD CONSTRAINT scans_check CHECK (project_id IS NOT NULL "
        "OR public_token_hash IS NOT NULL OR (trigger = 'observe' AND user_id IS NOT NULL))"
    )
    op.execute("ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_trigger_check")
    op.execute(
        "ALTER TABLE scans ADD CONSTRAINT scans_trigger_check "
        "CHECK (trigger IN ('manual', 'scheduled', 'ci', 'observe'))"
    )


def downgrade() -> None:
    # Only valid while no 'observe' scan exists; the downgrade refuses otherwise (no data loss).
    op.execute("ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_trigger_check")
    op.execute(
        "ALTER TABLE scans ADD CONSTRAINT scans_trigger_check CHECK (trigger IN ('manual', 'scheduled', 'ci'))"
    )
    op.execute("ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_check")
    op.execute(
        "ALTER TABLE scans ADD CONSTRAINT scans_check "
        "CHECK (project_id IS NOT NULL OR public_token_hash IS NOT NULL)"
    )
