"""Phase 1 schema: scheduled monitoring, alerts, and admin trusted domains (ADR-0003).

- projects: scan frequency + next run, and why a schedule was paused.
- notification_settings: one row per user (channels + which changes to alert on). The Slack
  webhook URL is a secret and is stored AES-GCM encrypted (AAD = user id), like TOTP secrets.
- notifications: one row per (scan, channel): makes sending idempotent (no duplicate alerts on
  retries) and is the user's alert history.
- admin_trusted_domains: hosts an ADMIN proved once; scans of exactly that host skip the proof
  prompt while the proof stays published (re-checked in the background, ADR-0003). Visible
  only to the owning admin and to 'system'.
- ownership_method gains 'trusted_domain' (project verified through an active trusted domain).
- scans.failed_checks: checks that could not run (so a diff never calls them "fixed").
- ScanDiff stays DERIVED (no table): computed from findings.fingerprint across scans.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-17
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


UPGRADE = [
    # ---- scheduled monitoring ----
    """ALTER TABLE projects
         ADD COLUMN scan_frequency text NOT NULL DEFAULT 'off'
             CHECK (scan_frequency IN ('off', 'daily', 'weekly')),
         ADD COLUMN next_scan_at timestamptz,
         ADD COLUMN schedule_paused_reason text
             CHECK (schedule_paused_reason IN ('ownership_lost'))""",
    """CREATE INDEX projects_due_idx ON projects (next_scan_at)
         WHERE scan_frequency <> 'off' AND schedule_paused_reason IS NULL""",
    "ALTER TABLE projects DROP CONSTRAINT projects_ownership_method_check",
    """ALTER TABLE projects ADD CONSTRAINT projects_ownership_method_check
         CHECK (ownership_method IN ('well_known', 'meta_tag', 'dns_txt', 'trusted_domain'))""",
    # Checks that could not run in a scan. A diff only compares checks that ran in BOTH scans,
    # so a failed check never shows up as "fixed" (or triggers a false all-clear alert).
    "ALTER TABLE scans ADD COLUMN failed_checks text[] NOT NULL DEFAULT '{}'",
    # diff lookups: "has this fingerprint appeared in an earlier scan of the project?"
    "CREATE INDEX findings_fingerprint_idx ON findings (fingerprint)",
    # ---- alerts ----
    """CREATE TABLE notification_settings (
        user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        email_enabled boolean NOT NULL DEFAULT true,
        slack_webhook_enc text,
        notify_new boolean NOT NULL DEFAULT true,
        notify_regression boolean NOT NULL DEFAULT true,
        notify_fixed boolean NOT NULL DEFAULT true,
        updated_at timestamptz NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE notifications (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        project_id uuid REFERENCES projects(id) ON DELETE CASCADE,
        scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
        channel text NOT NULL CHECK (channel IN ('email', 'slack')),
        status text NOT NULL CHECK (status IN ('pending', 'sent', 'failed', 'skipped')),
        new_count integer NOT NULL DEFAULT 0,
        regression_count integer NOT NULL DEFAULT 0,
        fixed_count integer NOT NULL DEFAULT 0,
        attempts integer NOT NULL DEFAULT 0,
        error text,
        created_at timestamptz NOT NULL DEFAULT now(),
        sent_at timestamptz
    )""",
    "CREATE UNIQUE INDEX notifications_scan_channel_key ON notifications (scan_id, channel)",
    "CREATE INDEX notifications_user_idx ON notifications (user_id, created_at DESC)",
    # ---- admin trusted domains (ADR-0003) ----
    """CREATE TABLE admin_trusted_domains (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        admin_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        host text NOT NULL CHECK (host = lower(host) AND host ~ '^[a-z0-9.-]{1,253}(:[0-9]{1,5})?$'),
        target_origin text NOT NULL,
        status text NOT NULL DEFAULT 'pending'
            CHECK (status IN ('pending', 'active', 'suspended', 'revoked')),
        verification_token text NOT NULL,
        method text CHECK (method IN ('well_known', 'meta_tag', 'dns_txt')),
        verified_at timestamptz,
        last_checked_at timestamptz,
        last_check_error text,
        suspended_at timestamptz,
        revoked_at timestamptz,
        created_at timestamptz NOT NULL DEFAULT now()
    )""",
    """CREATE UNIQUE INDEX admin_trusted_domains_live_key ON admin_trusted_domains (admin_user_id, host)
         WHERE status <> 'revoked'""",
    # ---- RLS ----
    "ALTER TABLE notification_settings ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE notifications ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE admin_trusted_domains ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY notification_settings_access ON notification_settings
       USING (user_id = app_user_id() OR app_role() = 'system')
       WITH CHECK (user_id = app_user_id() OR app_role() = 'system')""",
    # users READ their alert history; only the notifier ('system') writes it
    """CREATE POLICY notifications_read ON notifications FOR SELECT
       USING (user_id = app_user_id() OR app_is_privileged())""",
    """CREATE POLICY notifications_write ON notifications FOR ALL
       USING (app_role() = 'system') WITH CHECK (app_role() = 'system')""",
    # only the owning admin (role re-checked from the DB by the API) and 'system'
    """CREATE POLICY admin_trusted_domains_access ON admin_trusted_domains
       USING ((app_role() = 'admin' AND admin_user_id = app_user_id()) OR app_role() = 'system')
       WITH CHECK ((app_role() = 'admin' AND admin_user_id = app_user_id()) OR app_role() = 'system')""",
]


def _grants(role: str) -> list[str]:
    return [
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON notification_settings TO {role}",
        f"GRANT SELECT, INSERT, UPDATE ON notifications TO {role}",
        f"GRANT SELECT, INSERT, UPDATE ON admin_trusted_domains TO {role}",
    ]


DOWNGRADE = [
    "DROP TABLE IF EXISTS admin_trusted_domains",
    "DROP TABLE IF EXISTS notifications",
    "DROP TABLE IF EXISTS notification_settings",
    "DROP INDEX IF EXISTS findings_fingerprint_idx",
    "ALTER TABLE scans DROP COLUMN IF EXISTS failed_checks",
    # projects verified through a trusted domain fall back to "needs a proof"
    """UPDATE projects SET ownership_method = NULL, ownership_verified_at = NULL
       WHERE ownership_method = 'trusted_domain'""",
    "ALTER TABLE projects DROP CONSTRAINT projects_ownership_method_check",
    """ALTER TABLE projects ADD CONSTRAINT projects_ownership_method_check
         CHECK (ownership_method IN ('well_known', 'meta_tag', 'dns_txt'))""",
    "DROP INDEX IF EXISTS projects_due_idx",
    """ALTER TABLE projects DROP COLUMN IF EXISTS schedule_paused_reason,
         DROP COLUMN IF EXISTS next_scan_at, DROP COLUMN IF EXISTS scan_frequency""",
]


def upgrade() -> None:
    for stmt in [*UPGRADE, *_grants(_app_role())]:
        op.execute(stmt)


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
