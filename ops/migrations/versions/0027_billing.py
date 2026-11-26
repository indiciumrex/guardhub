"""Subscriptions and plan limits (Phase 5C): the mechanism, with charging OFF.

- billing_plans: per-plan limits (sites, manual scans per day, concurrent manual scans, the
  module tier by rank) and the trial length. Seeded with TODAY's behaviour for all three plans
  (25 sites, no practical scan cap), so nothing changes for anyone until the founder sets
  values. Prices are not stored here: they live with the payment provider (the founder's).
- subscriptions (existing table): one row per account. Adds the trial, the provider ids and
  updated_at. A guard trigger lets plan, status, trial and provider fields change only in an
  admin or system context: a customer can never upgrade themselves, even through an API bug.
- billing_events: incoming provider webhooks, stored once per (provider, event id), with a hash
  of the body, never the body.

Revision ID: 0027
Revises: 0026
Create Date: 2026-11-26
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


def upgrade() -> None:
    role = _app_role()
    for stmt in (
        """CREATE TABLE billing_plans (
            key text PRIMARY KEY CHECK (key IN ('free', 'pro', 'agency')),
            rank integer NOT NULL UNIQUE CHECK (rank BETWEEN 0 AND 9),
            max_sites integer NOT NULL CHECK (max_sites BETWEEN 1 AND 1000),
            scans_per_day integer NOT NULL CHECK (scans_per_day BETWEEN 1 AND 10000),
            concurrent_scans integer NOT NULL CHECK (concurrent_scans BETWEEN 1 AND 100),
            trial_days integer NOT NULL DEFAULT 0 CHECK (trial_days BETWEEN 0 AND 90),
            public boolean NOT NULL DEFAULT false,
            updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
            updated_at timestamptz NOT NULL DEFAULT now()
        )""",
        """INSERT INTO billing_plans (key, rank, max_sites, scans_per_day, concurrent_scans, trial_days, public)
           VALUES ('free', 0, 25, 1000, 25, 0, true),
                  ('pro', 1, 25, 1000, 25, 14, false),
                  ('agency', 2, 25, 1000, 25, 14, false)""",
        "ALTER TABLE billing_plans ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY billing_plans_read ON billing_plans FOR SELECT USING (true)",
        """CREATE POLICY billing_plans_write ON billing_plans FOR UPDATE
           USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
        f"GRANT SELECT, UPDATE ON billing_plans TO {role}",
        "ALTER TABLE subscriptions ADD CONSTRAINT subscriptions_one_per_user UNIQUE (user_id)",
        "ALTER TABLE subscriptions ADD COLUMN trial_ends_at timestamptz",
        "ALTER TABLE subscriptions ADD COLUMN trial_used boolean NOT NULL DEFAULT false",
        "ALTER TABLE subscriptions ADD COLUMN provider text CHECK (provider IS NULL OR length(provider) <= 32)",
        "ALTER TABLE subscriptions ADD COLUMN provider_customer_id text CHECK (length(provider_customer_id) <= 255)",
        "ALTER TABLE subscriptions ADD COLUMN provider_subscription_id text"
        " CHECK (length(provider_subscription_id) <= 255)",
        "ALTER TABLE subscriptions ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()",
        """ALTER TABLE subscriptions ADD CONSTRAINT subscriptions_status_check
           CHECK (status IN ('active', 'trialing', 'past_due', 'canceled'))""",
        f"""CREATE FUNCTION subscriptions_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF app_is_privileged() OR current_user <> '{role}' THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'subscriptions change only in an admin or system context' USING ERRCODE = '42501';
        END
        $$""",
        """CREATE TRIGGER subscriptions_guard BEFORE INSERT OR UPDATE ON subscriptions
           FOR EACH ROW EXECUTE FUNCTION subscriptions_guard()""",
        """CREATE TABLE billing_events (
            provider text NOT NULL CHECK (length(provider) <= 32),
            event_id text NOT NULL CHECK (length(event_id) <= 255),
            type text NOT NULL CHECK (length(type) <= 100),
            payload_sha256 text NOT NULL,
            received_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (provider, event_id)
        )""",
        "ALTER TABLE billing_events ENABLE ROW LEVEL SECURITY",
        """CREATE POLICY billing_events_system ON billing_events FOR ALL
           USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
        f"GRANT SELECT, INSERT ON billing_events TO {role}",
    ):
        op.execute(stmt)


def downgrade() -> None:
    for stmt in (
        "DROP TABLE IF EXISTS billing_events",
        "DROP TRIGGER IF EXISTS subscriptions_guard ON subscriptions",
        "DROP FUNCTION IF EXISTS subscriptions_guard()",
        "ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_status_check",
        "ALTER TABLE subscriptions DROP CONSTRAINT IF EXISTS subscriptions_one_per_user",
        "ALTER TABLE subscriptions DROP COLUMN IF EXISTS updated_at",
        "ALTER TABLE subscriptions DROP COLUMN IF EXISTS provider_subscription_id",
        "ALTER TABLE subscriptions DROP COLUMN IF EXISTS provider_customer_id",
        "ALTER TABLE subscriptions DROP COLUMN IF EXISTS provider",
        "ALTER TABLE subscriptions DROP COLUMN IF EXISTS trial_used",
        "ALTER TABLE subscriptions DROP COLUMN IF EXISTS trial_ends_at",
        "DROP TABLE IF EXISTS billing_plans",
    ):
        op.execute(stmt)
