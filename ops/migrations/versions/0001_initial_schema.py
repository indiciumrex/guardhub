"""Initial schema: core entities (§6), Row-Level Security, and an append-only AuditLog.

RLS model. Every request sets transaction-local settings (see guardhub_api/db/session.py):
  app.role        'user' | 'admin' | 'system' | 'anon'
  app.user_id     uuid of the authenticated user (user/admin)
  app.scan_token  keyed hash of an anonymous scan access token (anon)
A user sees only rows tied to their user_id. 'admin' and 'system' (internal service paths:
login lookup, event ingestion) see the management scope. The app role is NOT the table owner,
so RLS always applies to it.

Revision ID: 0001
Revises:
Create Date: 2026-11-16
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

TABLES = (
    "users", "projects", "target_verifications", "scans", "findings", "evidence",
    "trust_pages", "subscriptions", "modules", "ai_configs", "health_checks", "audit_logs",
)  # fmt: skip


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


SCHEMA = [
    "CREATE EXTENSION IF NOT EXISTS pgcrypto",
    # ---- RLS helper functions (read transaction-local settings) ----
    """CREATE FUNCTION app_user_id() RETURNS uuid LANGUAGE sql STABLE AS
       $$ SELECT NULLIF(current_setting('app.user_id', true), '')::uuid $$""",
    """CREATE FUNCTION app_role() RETURNS text LANGUAGE sql STABLE AS
       $$ SELECT COALESCE(NULLIF(current_setting('app.role', true), ''), 'none') $$""",
    """CREATE FUNCTION app_scan_token() RETURNS text LANGUAGE sql STABLE AS
       $$ SELECT NULLIF(current_setting('app.scan_token', true), '') $$""",
    """CREATE FUNCTION app_is_privileged() RETURNS boolean LANGUAGE sql STABLE AS
       $$ SELECT app_role() IN ('admin', 'system') $$""",
    # ---- core entities ----
    """CREATE TABLE users (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        email text NOT NULL CHECK (email = lower(email) AND length(email) <= 254),
        password_hash text NOT NULL,
        totp_secret text,
        totp_enabled boolean NOT NULL DEFAULT false,
        role text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
        locale text NOT NULL DEFAULT 'en',
        created_at timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE UNIQUE INDEX users_email_key ON users (email)",
    """CREATE TABLE projects (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
        target_url text NOT NULL,
        verification_token text NOT NULL,
        ownership_verified_at timestamptz,
        ownership_method text CHECK (ownership_method IN ('well_known', 'meta_tag', 'dns_txt')),
        created_at timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX projects_user_idx ON projects (user_id)",
    "CREATE UNIQUE INDEX projects_user_target_key ON projects (user_id, target_url)",
    """CREATE TABLE target_verifications (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid REFERENCES users(id) ON DELETE CASCADE,
        target_origin text NOT NULL,
        token text NOT NULL,
        method text CHECK (method IN ('well_known', 'meta_tag', 'dns_txt')),
        verified_at timestamptz,
        requester_ip_hash text,
        created_at timestamptz NOT NULL DEFAULT now(),
        expires_at timestamptz NOT NULL
    )""",
    """CREATE TABLE scans (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        project_id uuid REFERENCES projects(id) ON DELETE CASCADE,
        user_id uuid REFERENCES users(id) ON DELETE CASCADE,
        verification_id uuid REFERENCES target_verifications(id) ON DELETE SET NULL,
        target_url text NOT NULL,
        status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
        score integer CHECK (score BETWEEN 0 AND 100),
        trigger text NOT NULL DEFAULT 'manual' CHECK (trigger IN ('manual', 'scheduled', 'ci')),
        checks text[] NOT NULL DEFAULT '{}',
        public_token_hash text,
        error text,
        created_at timestamptz NOT NULL DEFAULT now(),
        started_at timestamptz,
        finished_at timestamptz,
        CHECK (project_id IS NOT NULL OR public_token_hash IS NOT NULL)
    )""",
    "CREATE INDEX scans_project_idx ON scans (project_id, created_at DESC)",
    "CREATE INDEX scans_user_idx ON scans (user_id)",
    "CREATE INDEX scans_created_idx ON scans (created_at DESC)",
    """CREATE TABLE findings (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        check_id text NOT NULL,
        finding_key text NOT NULL,
        severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
        title_key text NOT NULL,
        plain_summary text NOT NULL,
        fix_guidance text NOT NULL,
        params jsonb NOT NULL DEFAULT '{}'::jsonb,
        fingerprint text NOT NULL,
        evidence_ref uuid,
        status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'ignored')),
        created_at timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX findings_scan_idx ON findings (scan_id)",
    "CREATE UNIQUE INDEX findings_scan_fingerprint_key ON findings (scan_id, fingerprint)",
    """CREATE TABLE evidence (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        finding_id uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
        kind text NOT NULL CHECK (kind IN ('http_response', 'http_header', 'tls_handshake', 'dns_record')),
        location text NOT NULL,
        redacted_payload text NOT NULL,
        captured_at timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX evidence_finding_idx ON evidence (finding_id)",
    # ---- phase-1/2 entities: schema now, features later (§2.10) ----
    """CREATE TABLE trust_pages (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{3,64}$'),
        is_public boolean NOT NULL DEFAULT false,
        snapshot_at timestamptz
    )""",
    """CREATE TABLE subscriptions (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        plan text NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'agency')),
        status text NOT NULL DEFAULT 'active',
        current_period_end timestamptz
    )""",
    # ---- management & infrastructure ----
    """CREATE TABLE modules (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        key text NOT NULL UNIQUE,
        name text NOT NULL,
        category text NOT NULL,
        enabled_global boolean NOT NULL DEFAULT false,
        min_plan text NOT NULL DEFAULT 'free' CHECK (min_plan IN ('free', 'pro', 'agency')),
        rolled_out_at timestamptz
    )""",
    """CREATE TABLE ai_configs (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        provider text NOT NULL,
        api_key_ref text NOT NULL,
        enabled boolean NOT NULL DEFAULT false,
        updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
        updated_at timestamptz NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE health_checks (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        module_key text NOT NULL,
        status text NOT NULL CHECK (status IN ('ok', 'degraded', 'down')),
        error_rate double precision NOT NULL DEFAULT 0,
        latency_ms integer NOT NULL DEFAULT 0,
        checked_at timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX health_checks_module_idx ON health_checks (module_key, checked_at DESC)",
    """CREATE TABLE audit_logs (
        id bigserial PRIMARY KEY,
        actor text NOT NULL,
        action text NOT NULL,
        target text NOT NULL DEFAULT '',
        metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
        at timestamptz NOT NULL DEFAULT now()
    )""",
    "CREATE INDEX audit_logs_at_idx ON audit_logs (at DESC)",
    # AuditLog is append-only: block UPDATE/DELETE/TRUNCATE even for the owner role.
    """CREATE FUNCTION audit_logs_immutable() RETURNS trigger LANGUAGE plpgsql AS
       $$ BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END $$""",
    """CREATE TRIGGER audit_logs_no_update BEFORE UPDATE OR DELETE ON audit_logs
       FOR EACH ROW EXECUTE FUNCTION audit_logs_immutable()""",
    """CREATE TRIGGER audit_logs_no_truncate BEFORE TRUNCATE ON audit_logs
       FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_immutable()""",
    # ---- seed module registry: every new module ships DISABLED (§8.3, §12.4) ----
    """INSERT INTO modules (key, name, category, enabled_global) VALUES
       ('exposed_env', 'Exposed secrets & repository files', 'exposure', false),
       ('security_headers', 'Security headers', 'hardening', false),
       ('tls_cert', 'HTTPS & certificate', 'transport', false),
       ('open_admin', 'Open admin & debug endpoints', 'exposure', false),
       ('default_creds', 'Default credentials & installers', 'access', false),
       ('info_leak', 'Information leaks', 'disclosure', false)""",
]

RLS = [
    *[f"ALTER TABLE {t} ENABLE ROW LEVEL SECURITY" for t in TABLES],
    """CREATE POLICY users_access ON users
       USING (id = app_user_id() OR app_is_privileged())
       WITH CHECK (id = app_user_id() OR app_is_privileged())""",
    """CREATE POLICY projects_access ON projects
       USING (user_id = app_user_id() OR app_is_privileged())
       WITH CHECK (user_id = app_user_id() OR app_role() = 'system')""",
    """CREATE POLICY verifications_access ON target_verifications
       USING (app_role() = 'system' OR (user_id IS NOT NULL AND user_id = app_user_id()))
       WITH CHECK (app_role() = 'system' OR (user_id IS NOT NULL AND user_id = app_user_id()))""",
    """CREATE POLICY scans_access ON scans
       USING (user_id = app_user_id() OR app_is_privileged()
              OR (public_token_hash IS NOT NULL AND public_token_hash = app_scan_token()))
       WITH CHECK (user_id = app_user_id() OR app_role() = 'system')""",
    # child rows inherit visibility from their scan (the subquery is itself filtered by RLS)
    """CREATE POLICY findings_access ON findings
       USING (EXISTS (SELECT 1 FROM scans s WHERE s.id = findings.scan_id))
       WITH CHECK (app_role() = 'system')""",
    """CREATE POLICY evidence_access ON evidence
       USING (EXISTS (SELECT 1 FROM findings f WHERE f.id = evidence.finding_id))
       WITH CHECK (app_role() = 'system')""",
    """CREATE POLICY trust_pages_access ON trust_pages
       USING (EXISTS (SELECT 1 FROM projects p WHERE p.id = trust_pages.project_id))""",
    """CREATE POLICY subscriptions_access ON subscriptions
       USING (user_id = app_user_id() OR app_is_privileged())
       WITH CHECK (app_is_privileged())""",
    "CREATE POLICY modules_read ON modules FOR SELECT USING (true)",
    """CREATE POLICY modules_write ON modules FOR UPDATE
       USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
    "CREATE POLICY ai_configs_access ON ai_configs USING (app_is_privileged()) WITH CHECK (app_is_privileged())",
    """CREATE POLICY health_checks_access ON health_checks
       USING (app_is_privileged()) WITH CHECK (app_role() = 'system')""",
    "CREATE POLICY audit_logs_insert ON audit_logs FOR INSERT WITH CHECK (true)",
    "CREATE POLICY audit_logs_read ON audit_logs FOR SELECT USING (app_is_privileged())",
]


def _grants(role: str) -> list[str]:
    return [
        f"""DO $$ BEGIN
              IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                CREATE ROLE {role} NOLOGIN;
              END IF;
            END $$""",
        f"GRANT USAGE ON SCHEMA public TO {role}",
        f"""GRANT SELECT, INSERT, UPDATE, DELETE ON users, projects, target_verifications, scans,
            findings, evidence, trust_pages, subscriptions, ai_configs TO {role}""",
        f"GRANT SELECT, UPDATE ON modules TO {role}",
        f"GRANT SELECT, INSERT, DELETE ON health_checks TO {role}",
        f"GRANT SELECT, INSERT ON audit_logs TO {role}",
        f"GRANT USAGE ON SEQUENCE audit_logs_id_seq TO {role}",
    ]


def upgrade() -> None:
    for stmt in [*SCHEMA, *RLS, *_grants(_app_role())]:
        op.execute(stmt)


def downgrade() -> None:
    for t in reversed(TABLES):
        op.execute(f"DROP TABLE IF EXISTS {t} CASCADE")
    for fn in ("audit_logs_immutable", "app_is_privileged", "app_scan_token", "app_role", "app_user_id"):
        op.execute(f"DROP FUNCTION IF EXISTS {fn}()")
