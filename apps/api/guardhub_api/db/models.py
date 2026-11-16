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


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[uuid.UUID] = _pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(Text)
    target_url: Mapped[str] = mapped_column(Text)
    verification_token: Mapped[str] = mapped_column(Text)
    ownership_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ownership_method: Mapped[str | None] = mapped_column(String)
    created_at: Mapped[datetime] = _now()


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


class Module(Base):
    __tablename__ = "modules"
    id: Mapped[uuid.UUID] = _pk()
    key: Mapped[str] = mapped_column(Text, unique=True)
    name: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(Text)
    enabled_global: Mapped[bool] = mapped_column(Boolean, default=False)
    min_plan: Mapped[str] = mapped_column(String, default="free")
    rolled_out_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


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
