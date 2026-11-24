"""Phase 4B active-testing safety (ADR-0008): consent records, the append-only request log, and
the active modules registered DISABLED.

- modules: active_xss, active_sqli, active_redirect, active_cors, active_ssrf, active_idor, all
  off. Switching one on in the admin is refused until it has a measured scorecard that meets the
  gate (Gate M), and the scanner refuses active jobs anyway unless SCANNER_ACTIVE_ENABLED=true.
- active_consents: what the customer agreed to (origin, excluded paths, checks, consent text
  version + sha256, when). Rows are never deleted or rewritten: the only change allowed is
  revoking (revoked_at NULL -> a time), plus the foreign keys being nulled when a user or project
  is deleted. The consent TEXT itself is the founder's (ADR-0008 §8, legal review); no route
  writes consents until it is approved.
- active_request_log: every request an active scan sent (scanner event active.request_log).
  Append-only (UPDATE/DELETE/TRUNCATE raise). No foreign key, so deleting a scan or account
  never erases the record of what was sent to a third-party server.

EXPAND-ONLY: the previous release ignores the new tables and the disabled modules.

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-24
"""

from __future__ import annotations

import os
import re

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

MODULES = [
    ("active_xss", "Reflected cross-site scripting (active test)", "active"),
    ("active_sqli", "SQL injection (active test)", "active"),
    ("active_redirect", "Open redirect (active test)", "active"),
    ("active_cors", "Cross-origin access with credentials (active test)", "active"),
    ("active_ssrf", "Server-side request forgery (active test)", "active"),
    ("active_idor", "Access to other accounts' data (active test)", "active"),
]


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    """CREATE TABLE active_consents (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid REFERENCES users(id) ON DELETE SET NULL,
        project_id uuid REFERENCES projects(id) ON DELETE SET NULL,
        origin text NOT NULL CHECK (length(origin) <= 300),
        excluded_paths text[] NOT NULL DEFAULT '{}',
        checks text[] NOT NULL CHECK (cardinality(checks) > 0),
        consent_version text NOT NULL CHECK (length(consent_version) <= 64),
        consent_sha256 text NOT NULL CHECK (consent_sha256 ~ '^[0-9a-f]{64}$'),
        accepted_at timestamptz NOT NULL DEFAULT now(),
        revoked_at timestamptz
    )""",
    "CREATE INDEX active_consents_project_idx ON active_consents (project_id, accepted_at DESC)",
    # only revocation (once) and FK nulling may change a row; nothing may delete one
    """CREATE FUNCTION active_consents_guard() RETURNS trigger LANGUAGE plpgsql AS $$
       BEGIN
         IF TG_OP <> 'UPDATE' THEN
           RAISE EXCEPTION 'active_consents rows are never deleted';
         END IF;
         IF NEW.id IS DISTINCT FROM OLD.id OR NEW.origin IS DISTINCT FROM OLD.origin
            OR NEW.excluded_paths IS DISTINCT FROM OLD.excluded_paths
            OR NEW.checks IS DISTINCT FROM OLD.checks
            OR NEW.consent_version IS DISTINCT FROM OLD.consent_version
            OR NEW.consent_sha256 IS DISTINCT FROM OLD.consent_sha256
            OR NEW.accepted_at IS DISTINCT FROM OLD.accepted_at
            OR (NEW.user_id IS DISTINCT FROM OLD.user_id AND NEW.user_id IS NOT NULL)
            OR (NEW.project_id IS DISTINCT FROM OLD.project_id AND NEW.project_id IS NOT NULL)
            OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at) THEN
           RAISE EXCEPTION 'active_consents: only revocation may change a consent';
         END IF;
         RETURN NEW;
       END $$""",
    """CREATE TRIGGER active_consents_guard BEFORE UPDATE OR DELETE ON active_consents
       FOR EACH ROW EXECUTE FUNCTION active_consents_guard()""",
    """CREATE TRIGGER active_consents_no_truncate BEFORE TRUNCATE ON active_consents
       FOR EACH STATEMENT EXECUTE FUNCTION active_consents_guard()""",
    "ALTER TABLE active_consents ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY active_consents_read ON active_consents FOR SELECT
       USING (user_id = app_user_id() OR app_is_privileged())""",
    """CREATE POLICY active_consents_insert ON active_consents FOR INSERT
       WITH CHECK (user_id = app_user_id() OR app_role() = 'system')""",
    """CREATE POLICY active_consents_revoke ON active_consents FOR UPDATE
       USING (user_id = app_user_id() OR app_is_privileged())
       WITH CHECK (user_id = app_user_id() OR app_is_privileged() OR user_id IS NULL)""",
    """CREATE TABLE active_request_log (
        id bigserial PRIMARY KEY,
        scan_id uuid NOT NULL,
        consent_id uuid NOT NULL,
        at timestamptz NOT NULL,
        module text NOT NULL,
        payload_id text NOT NULL,
        payload_sha256 text,
        method text NOT NULL CHECK (method = 'GET'),
        path text NOT NULL,
        param text,
        session text CHECK (session IS NULL OR session IN ('A', 'B')),
        status integer,
        length integer,
        latency_ms bigint,
        outcome text NOT NULL,
        recorded_at timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX active_request_log_scan_idx ON active_request_log (scan_id, id)",
    """CREATE FUNCTION active_request_log_immutable() RETURNS trigger LANGUAGE plpgsql AS
       $$ BEGIN RAISE EXCEPTION 'active_request_log is append-only'; END $$""",
    """CREATE TRIGGER active_request_log_no_update BEFORE UPDATE OR DELETE ON active_request_log
       FOR EACH ROW EXECUTE FUNCTION active_request_log_immutable()""",
    """CREATE TRIGGER active_request_log_no_truncate BEFORE TRUNCATE ON active_request_log
       FOR EACH STATEMENT EXECUTE FUNCTION active_request_log_immutable()""",
    "ALTER TABLE active_request_log ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY active_request_log_insert ON active_request_log FOR INSERT
       WITH CHECK (app_role() = 'system')""",
    # the scan's owner sees what was sent to their site (the scans subquery is itself RLS-filtered)
    """CREATE POLICY active_request_log_read ON active_request_log FOR SELECT
       USING (app_is_privileged()
              OR EXISTS (SELECT 1 FROM scans s WHERE s.id = active_request_log.scan_id))""",
]


def _grants(role: str) -> list[str]:
    return [
        f"GRANT SELECT, INSERT, UPDATE ON active_consents TO {role}",
        f"GRANT SELECT, INSERT ON active_request_log TO {role}",
        f"GRANT USAGE ON SEQUENCE active_request_log_id_seq TO {role}",
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
    delete = sa.text("DELETE FROM modules WHERE key = :key")
    for key, _, _ in MODULES:
        op.get_bind().execute(delete, {"key": key})
    op.execute("DROP TABLE IF EXISTS active_request_log")
    op.execute("DROP FUNCTION IF EXISTS active_request_log_immutable()")
    op.execute("DROP TABLE IF EXISTS active_consents")
    op.execute("DROP FUNCTION IF EXISTS active_consents_guard()")
