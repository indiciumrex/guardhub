"""Signed outgoing webhooks (Admin Panel, Prompt 2 §4).

webhooks: an admin's HTTPS endpoint for events (scan.completed for the admin's own scans,
ops_alert.opened, ping). The signing secret is AES-GCM encrypted (AAD = webhook id) and shown
once. webhook_deliveries: the delivery history (status, attempts, HTTP status, error, and a hash
of the payload, never the payload). Delivery runs in api-jobs behind SSRF guards
(webhooks/safety.py).

Admin/system only (RLS). EXPAND-ONLY: the previous release ignores the new table.

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-26
"""

from __future__ import annotations

import os
import re

from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def _app_role() -> str:
    role = os.environ.get("GUARDHUB_APP_DB_USER", "guardhub_app")
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise SystemExit("GUARDHUB_APP_DB_USER must be a plain lowercase identifier")
    return role


EVENTS = "ARRAY['scan.completed', 'ops_alert.opened', 'ping']::text[]"

UPGRADE = [
    f"""CREATE TABLE webhooks (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        name text NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
        url text NOT NULL CHECK (url LIKE 'https://%' AND length(url) <= 2048),
        events text[] NOT NULL CHECK (cardinality(events) >= 1 AND events <@ {EVENTS}),
        secret_enc text NOT NULL,
        enabled boolean NOT NULL DEFAULT true,
        created_at timestamptz NOT NULL DEFAULT now(),
        updated_at timestamptz NOT NULL DEFAULT now()
    )""",
    """CREATE TABLE webhook_deliveries (
        id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
        webhook_id uuid NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
        event text NOT NULL,
        event_id text NOT NULL CHECK (length(event_id) <= 100),
        status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed')),
        attempts integer NOT NULL DEFAULT 0,
        http_status integer,
        error text CHECK (length(error) <= 200),
        payload_sha256 text,
        created_at timestamptz NOT NULL DEFAULT now(),
        delivered_at timestamptz,
        UNIQUE (webhook_id, event_id)
    )""",
    "CREATE INDEX webhook_deliveries_recent_idx ON webhook_deliveries (webhook_id, created_at DESC)",
    "ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY",
    """CREATE POLICY webhooks_admin ON webhooks FOR ALL
       USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
    """CREATE POLICY webhook_deliveries_admin ON webhook_deliveries FOR ALL
       USING (app_is_privileged()) WITH CHECK (app_is_privileged())""",
]

DOWNGRADE = ["DROP TABLE IF EXISTS webhook_deliveries", "DROP TABLE IF EXISTS webhooks"]


def upgrade() -> None:
    for stmt in UPGRADE:
        op.execute(stmt)
    role = _app_role()
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON webhooks TO {role}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON webhook_deliveries TO {role}")


def downgrade() -> None:
    for stmt in DOWNGRADE:
        op.execute(stmt)
