"""Phase 3 schema: GitHub repository scanning (ADR-0006).

- github_installations: a GitHub App installation bound to ONE GuardHub user. No token column:
  tokens are minted per scan and revoked after it. One live row per installation (a second
  account gets a unique violation → 409). Same RLS shape as projects.
- projects: kind (site | repo) plus the repository's GitHub id, owner/name and installation.
  ownership_method gains 'github_app'. A repo project's target_url is its GitHub URL, so the
  existing (user_id, target_url) uniqueness also keeps one project per repository.
- modules: dependency_vulns and repo_secrets, DISABLED (ADR-0004: measured before switched on).

Expand-only: the release still serving keeps working on this schema (kind defaults to 'site').

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-21
"""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

MODULES = [
    ("dependency_vulns", "Vulnerable dependencies (CVE)", "repo"),
    ("repo_secrets", "Secrets committed to the repository", "repo"),
]


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    """CREATE TABLE github_installations (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        installation_id bigint NOT NULL CHECK (installation_id > 0),
        account_login text NOT NULL CHECK (length(account_login) BETWEEN 1 AND 100),
        account_type text NOT NULL CHECK (account_type IN ('User', 'Organization')),
        created_at timestamptz NOT NULL DEFAULT now(),
        revoked_at timestamptz
    )""",
    """CREATE UNIQUE INDEX github_installations_live_key ON github_installations (installation_id)
         WHERE revoked_at IS NULL""",
    "CREATE INDEX github_installations_user_idx ON github_installations (user_id)",
    """ALTER TABLE projects
         ADD COLUMN kind text NOT NULL DEFAULT 'site' CHECK (kind IN ('site', 'repo')),
         ADD COLUMN github_installation_id uuid REFERENCES github_installations(id) ON DELETE SET NULL,
         ADD COLUMN repo_id bigint CHECK (repo_id IS NULL OR repo_id > 0),
         ADD COLUMN repo_full_name text
             CHECK (repo_full_name IS NULL OR length(repo_full_name) BETWEEN 3 AND 140),
         ADD CONSTRAINT projects_repo_fields
             CHECK (kind = 'site' OR (repo_id IS NOT NULL AND repo_full_name IS NOT NULL))""",
    "CREATE UNIQUE INDEX projects_user_repo_key ON projects (user_id, repo_id) WHERE kind = 'repo'",
    "ALTER TABLE projects DROP CONSTRAINT projects_ownership_method_check",
    """ALTER TABLE projects ADD CONSTRAINT projects_ownership_method_check
         CHECK (ownership_method IN ('well_known', 'meta_tag', 'dns_txt', 'trusted_domain', 'github_app'))""",
    "ALTER TABLE github_installations ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY github_installations_access ON github_installations
       USING (user_id = app_user_id() OR app_is_privileged())
       WITH CHECK (user_id = app_user_id() OR app_role() = 'system')""",
]


def _grants(role: str) -> list[str]:
    # No DELETE: disconnecting marks the row revoked (kept for the audit trail); account deletion
    # removes it through the users foreign key.
    return [f"GRANT SELECT, INSERT, UPDATE ON github_installations TO {role}"]


DOWNGRADE = [
    "DELETE FROM modules WHERE key IN ('dependency_vulns', 'repo_secrets')",
    # repo projects cannot exist without the columns: their scans and findings go with them
    "DELETE FROM projects WHERE kind = 'repo'",
    "ALTER TABLE projects DROP CONSTRAINT projects_ownership_method_check",
    """ALTER TABLE projects ADD CONSTRAINT projects_ownership_method_check
         CHECK (ownership_method IN ('well_known', 'meta_tag', 'dns_txt', 'trusted_domain'))""",
    "DROP INDEX IF EXISTS projects_user_repo_key",
    """ALTER TABLE projects DROP CONSTRAINT IF EXISTS projects_repo_fields,
         DROP COLUMN IF EXISTS repo_full_name, DROP COLUMN IF EXISTS repo_id,
         DROP COLUMN IF EXISTS github_installation_id, DROP COLUMN IF EXISTS kind""",
    "DROP TABLE IF EXISTS github_installations",
]


def upgrade() -> None:
    for stmt in [*UPGRADE, *_grants(_app_role())]:
        op.execute(stmt)
    insert = sa.text(
        "INSERT INTO modules (key, name, category, enabled_global) "
        "VALUES (:key, :name, :category, false) ON CONFLICT (key) DO NOTHING"
    )
    for key, name, category in MODULES:
        op.get_bind().execute(insert, {"key": key, "name": name, "category": category})


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
