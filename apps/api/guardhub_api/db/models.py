"""SQLAlchemy models mirroring ops/migrations (the SQL migrations are the source of truth).

These are mapping classes only. There's no autogenerate: schema changes are written as reviewed
SQL migrations so the RLS policies stay explicit.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ARRAY, BigInteger, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _pk() -> Mapped[uuid.UUID]:
    return mapped_column(UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid())


def _now() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = _pk()
    email: Mapped[str] = mapped_column(Text)
    password_hash: Mapped[str] = mapped_column(Text)
    totp_secret: Mapped[str | None] = mapped_column(Text)  # AES-GCM ciphertext, never plaintext
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    role: Mapped[str] = mapped_column(String, default="user")
    locale: Mapped[str] = mapped_column(String, default="en")
    created_at: Mapped[datetime] = _now()
    disabled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    disabled_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    display_name: Mapped[str | None] = mapped_column(Text)  # the holder's own; never authorisation
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(Text)
    target_url: Mapped[str] = mapped_column(Text)
    verification_token: Mapped[str] = mapped_column(Text)
    ownership_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ownership_method: Mapped[str | None] = mapped_column(String)
    scan_frequency: Mapped[str] = mapped_column(String, default="off")  # off | daily | weekly
    next_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    schedule_paused_reason: Mapped[str | None] = mapped_column(String)  # ownership_lost
    # Repository projects (ADR-0006): kind "repo", ownership proven by a GitHub App installation.
    kind: Mapped[str] = mapped_column(String, default="site")  # site | repo
    github_installation_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("github_installations.id"))
    repo_id: Mapped[int | None] = mapped_column(BigInteger)  # GitHub's stable numeric repository id
    repo_full_name: Mapped[str | None] = mapped_column(Text)  # owner/name, refreshed from GitHub
    created_at: Mapped[datetime] = _now()


class GitHubInstallation(Base):
    """A GitHub App installation bound to one GuardHub user (ADR-0006 §1-§4). No token is stored:
    tokens are minted per scan from the App's private key, narrowed to one repository."""

    __tablename__ = "github_installations"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    installation_id: Mapped[int] = mapped_column(BigInteger)
    account_login: Mapped[str] = mapped_column(Text)
    account_type: Mapped[str] = mapped_column(String)  # User | Organization
    created_at: Mapped[datetime] = _now()
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TargetVerification(Base):
    __tablename__ = "target_verifications"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    target_origin: Mapped[str] = mapped_column(Text)
    token: Mapped[str] = mapped_column(Text)
    method: Mapped[str | None] = mapped_column(String)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    requester_ip_hash: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[uuid.UUID] = _pk()
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    verification_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("target_verifications.id"))
    target_url: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="queued")
    score: Mapped[int | None] = mapped_column(Integer)
    trigger: Mapped[str] = mapped_column(String, default="manual")
    checks: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    failed_checks: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)  # could not run
    public_token_hash: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[uuid.UUID] = _pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    check_id: Mapped[str] = mapped_column(Text)
    finding_key: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String)
    title_key: Mapped[str] = mapped_column(Text)
    plain_summary: Mapped[str] = mapped_column(Text)  # i18n key (§6: translation-keyed)
    fix_guidance: Mapped[str] = mapped_column(Text)  # i18n key
    params: Mapped[dict[str, str]] = mapped_column(JSONB, default=dict)
    fingerprint: Mapped[str] = mapped_column(Text)
    evidence_ref: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    status: Mapped[str] = mapped_column(String, default="open")
    created_at: Mapped[datetime] = _now()


class Evidence(Base):
    __tablename__ = "evidence"
    id: Mapped[uuid.UUID] = _pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"))
    kind: Mapped[str] = mapped_column(String)
    location: Mapped[str] = mapped_column(Text)
    redacted_payload: Mapped[str] = mapped_column(Text)  # masked by scanner AND encrypted at rest
    captured_at: Mapped[datetime] = _now()


class NotificationSettings(Base):
    """Per-user alert preferences (Phase 1). The Slack webhook URL is a secret: encrypted."""

    __tablename__ = "notification_settings"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), primary_key=True)
    email_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    slack_webhook_enc: Mapped[str | None] = mapped_column(Text)  # AES-GCM, AAD = user id
    notify_new: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_regression: Mapped[bool] = mapped_column(Boolean, default=True)
    notify_fixed: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = _now()


class Notification(Base):
    """One alert per (scan, channel): idempotent sending + the user's alert history."""

    __tablename__ = "notifications"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id"))
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    channel: Mapped[str] = mapped_column(String)  # email | slack
    status: Mapped[str] = mapped_column(String)  # pending | sent | failed | skipped
    new_count: Mapped[int] = mapped_column(Integer, default=0)
    regression_count: Mapped[int] = mapped_column(Integer, default=0)
    fixed_count: Mapped[int] = mapped_column(Integer, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class NotificationEvent(Base):
    """An alert that is not about a scan ('monitoring_paused' | 'test'), one per (event, channel).

    A separate table (migration 0004) so the previous release, which requires a scan id on every
    `notifications` row, keeps working after a rollback."""

    __tablename__ = "notification_events"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    project_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("projects.id"))
    kind: Mapped[str] = mapped_column(String)  # monitoring_paused | test
    dedupe_key: Mapped[str] = mapped_column(Text)  # the alert job's unique id
    channel: Mapped[str] = mapped_column(String)  # email | slack
    status: Mapped[str] = mapped_column(String)  # pending | sent | failed | skipped
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AdminTrustedDomain(Base):
    """A host an admin proved once (ADR-0003). Exact host only; re-checked in the background."""

    __tablename__ = "admin_trusted_domains"
    id: Mapped[uuid.UUID] = _pk()
    admin_user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    host: Mapped[str] = mapped_column(Text)  # lowercase host[:port]
    target_origin: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="pending")  # pending|active|suspended|revoked
    verification_token: Mapped[str] = mapped_column(Text)
    method: Mapped[str | None] = mapped_column(String)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_check_error: Mapped[str | None] = mapped_column(Text)
    suspended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()


class Module(Base):
    __tablename__ = "modules"
    id: Mapped[uuid.UUID] = _pk()
    key: Mapped[str] = mapped_column(Text, unique=True)
    name: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text)
    enabled_global: Mapped[bool] = mapped_column(Boolean, default=False)
    min_plan: Mapped[str] = mapped_column(String, default="free")
    rolled_out_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # kept out of new scans without being switched off (migration 0017)
    maintenance: Mapped[bool] = mapped_column(Boolean, default=False)


class AIConfig(Base):
    __tablename__ = "ai_configs"
    id: Mapped[uuid.UUID] = _pk()
    provider: Mapped[str] = mapped_column(Text)
    api_key_ref: Mapped[str] = mapped_column(Text)  # encrypted reference, never a raw key
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"))
    updated_at: Mapped[datetime] = _now()


class HealthCheck(Base):
    __tablename__ = "health_checks"
    id: Mapped[uuid.UUID] = _pk()
    module_key: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String)
    error_rate: Mapped[float] = mapped_column(Float, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    checked_at: Mapped[datetime] = _now()


class AuditLog(Base):
    __tablename__ = "audit_logs"
    # No implicit RETURNING: writers may append audit rows but RLS forbids them reading any back.
    __table_args__ = {"implicit_returning": False}  # noqa: RUF012 — SQLAlchemy declarative API
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    actor: Mapped[str] = mapped_column(Text)
    action: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text, default="")
    metadata_: Mapped[dict[str, str]] = mapped_column("metadata", JSONB, default=dict)
    at: Mapped[datetime] = _now()


class PlatformSetting(Base):
    """An admin override of one registry tunable (platform/registry.py), migration 0019. Admin/system only."""

    __tablename__ = "platform_settings"
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[object] = mapped_column(JSONB)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    updated_at: Mapped[datetime] = _now()


class OpsAlertRule(Base):
    """An operational alert rule for admins (migration 0020). Admin/system only."""

    __tablename__ = "ops_alert_rules"
    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    threshold: Mapped[int] = mapped_column(Integer)
    window_minutes: Mapped[int] = mapped_column(Integer)
    email: Mapped[bool] = mapped_column(Boolean, default=True)
    muted_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    escalate_after_minutes: Mapped[int | None] = mapped_column(Integer)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    updated_at: Mapped[datetime] = _now()


class OpsAlert(Base):
    """One operational alert (migration 0020): at most one unresolved per kind."""

    __tablename__ = "ops_alerts"
    id: Mapped[uuid.UUID] = _pk()
    kind: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="open")
    value: Mapped[int] = mapped_column(Integer)
    threshold: Mapped[int] = mapped_column(Integer)
    detail: Mapped[dict[str, object]] = mapped_column(JSONB, default=dict)
    opened_at: Mapped[datetime] = _now()
    last_seen_at: Mapped[datetime] = _now()
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    emailed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ReportSchedule(Base):
    """A scheduled platform summary e-mail (migration 0021). Admin/system only."""

    __tablename__ = "report_schedules"
    frequency: Mapped[str] = mapped_column(Text, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    updated_at: Mapped[datetime] = _now()


class ApiKey(Base):
    """An integration API key (migration 0022): keyed hash only. Admin/system only."""

    __tablename__ = "api_keys"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(Text)
    prefix: Mapped[str] = mapped_column(Text)
    key_hash: Mapped[str] = mapped_column(Text)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(Text))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))


class Webhook(Base):
    """A signed outgoing webhook (migration 0023). Admin/system only."""

    __tablename__ = "webhooks"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(Text)
    url: Mapped[str] = mapped_column(Text)
    events: Mapped[list[str]] = mapped_column(ARRAY(Text))
    secret_enc: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()


class WebhookDelivery(Base):
    """One delivery of one event to one webhook (migration 0023): status only, never the payload."""

    __tablename__ = "webhook_deliveries"
    id: Mapped[uuid.UUID] = _pk()
    webhook_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("webhooks.id"))
    event: Mapped[str] = mapped_column(Text)
    event_id: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String, default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    http_status: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    payload_sha256: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AdminInvite(Base):
    """A one-time admin invitation (migration 0024): only the token's keyed hash. Admin/system only."""

    __tablename__ = "admin_invites"
    id: Mapped[uuid.UUID] = _pk()
    email: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(Text)
    invited_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    created_at: Mapped[datetime] = _now()
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    accepted_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RecoveryCode(Base):
    """A single-use two-factor recovery code (migration 0026): keyed hash only."""

    __tablename__ = "recovery_codes"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    code_hash: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class BillingPlan(Base):
    """Per-plan limits (migration 0027). Readable by everyone, changed by admins only."""

    __tablename__ = "billing_plans"
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    rank: Mapped[int] = mapped_column(Integer)
    max_sites: Mapped[int] = mapped_column(Integer)
    scans_per_day: Mapped[int] = mapped_column(Integer)
    concurrent_scans: Mapped[int] = mapped_column(Integer)
    trial_days: Mapped[int] = mapped_column(Integer, default=0)
    public: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    updated_at: Mapped[datetime] = _now()


class Subscription(Base):
    """One account's plan (migration 0001, extended in 0027). Changed only in admin/system context."""

    __tablename__ = "subscriptions"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    plan: Mapped[str] = mapped_column(Text, default="free")
    status: Mapped[str] = mapped_column(Text, default="active")
    current_period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    trial_used: Mapped[bool] = mapped_column(Boolean, default=False)
    provider: Mapped[str | None] = mapped_column(Text)
    provider_customer_id: Mapped[str | None] = mapped_column(Text)
    provider_subscription_id: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = _now()


class BillingEvent(Base):
    """An incoming provider webhook, stored once (migration 0027): a hash of the body only."""

    __tablename__ = "billing_events"
    provider: Mapped[str] = mapped_column(Text, primary_key=True)
    event_id: Mapped[str] = mapped_column(Text, primary_key=True)
    type: Mapped[str] = mapped_column(Text)
    payload_sha256: Mapped[str] = mapped_column(Text)
    received_at: Mapped[datetime] = _now()


class FindingTriage(Base):
    """The admin's verdict on one finding group (fingerprint), migration 0017. Admin/system only."""

    __tablename__ = "finding_triage"
    fingerprint: Mapped[str] = mapped_column(Text, primary_key=True)
    check_id: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String)  # verified | accepted | false_positive | resolved
    note: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"))
    updated_at: Mapped[datetime] = _now()


class ActiveConsent(Base):
    """What a customer agreed to for active tests (ADR-0008). Only revocation may change a row."""

    __tablename__ = "active_consents"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL")
    )
    origin: Mapped[str] = mapped_column(Text)
    excluded_paths: Mapped[list[str]] = mapped_column(ARRAY(Text), default=list)
    checks: Mapped[list[str]] = mapped_column(ARRAY(Text))
    consent_version: Mapped[str] = mapped_column(Text)
    consent_sha256: Mapped[str] = mapped_column(Text)
    accepted_at: Mapped[datetime] = _now()
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ActiveRequestLog(Base):
    """One request an active scan sent (append-only; ADR-0008 §6)."""

    __tablename__ = "active_request_log"
    # writers append without reading back (the system context may, but keep inserts plain)
    __table_args__ = {"implicit_returning": False}  # noqa: RUF012 — SQLAlchemy declarative API
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    consent_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    module: Mapped[str] = mapped_column(Text)
    payload_id: Mapped[str] = mapped_column(Text)
    payload_sha256: Mapped[str | None] = mapped_column(Text)
    method: Mapped[str] = mapped_column(Text)
    path: Mapped[str] = mapped_column(Text)
    param: Mapped[str | None] = mapped_column(Text)
    session: Mapped[str | None] = mapped_column(Text)
    status: Mapped[int | None] = mapped_column(Integer)
    length: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int | None] = mapped_column(BigInteger)
    outcome: Mapped[str] = mapped_column(Text)
    recorded_at: Mapped[datetime] = _now()
