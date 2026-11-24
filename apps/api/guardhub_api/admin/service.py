"""Minimal admin capabilities for the MVP (§8.3): lists, module toggles, health, audit, AI status.

Runs under the 'admin' RLS context. Callers must already have passed `admin_session` (role
re-read from the DB, MFA complete). It never exposes secrets: no password hashes, TOTP secrets
or token hashes.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from guardhub_api.active import kill
from guardhub_api.ai.provider import AIStatus
from guardhub_api.ai.provider import status as ai_status
from guardhub_api.auth import repository as user_repo
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit
from guardhub_api.common.redis import get_redis
from guardhub_api.config import get_settings
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.health import service as health
from guardhub_api.modules import registry
from guardhub_api.scans import repository as scan_repo
from guardhub_api.scans import service as scan_service
from guardhub_api.scans.schemas import ScanSummary


class AdminUserView(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    locale: str
    totp_enabled: bool
    created_at: datetime


class AuditView(BaseModel):
    id: int
    actor: str
    action: str
    target: str
    at: datetime


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="admin", user_id=claims.user_id)


async def list_users(claims: SessionClaims, limit: int, offset: int) -> list[AdminUserView]:
    async with db_session(_ctx(claims)) as session:
        users = await user_repo.list_users(session, limit, offset)
    return [
        AdminUserView(
            id=u.id,
            email=u.email,
            role=u.role,
            locale=u.locale,
            totp_enabled=u.totp_enabled,
            created_at=u.created_at,
        )
        for u in users
    ]


async def list_scans(claims: SessionClaims, limit: int, offset: int) -> list[ScanSummary]:
    async with db_session(_ctx(claims)) as session:
        return await scan_service.summaries(session, await scan_repo.list_recent(session, limit, offset))


async def list_modules(claims: SessionClaims) -> list[registry.ModuleView]:
    async with db_session(_ctx(claims)) as session:
        return await registry.list_modules(session)


async def toggle_module(claims: SessionClaims, key: str, enabled: bool) -> registry.ModuleView:
    async with db_session(_ctx(claims)) as session:
        return await registry.set_enabled(session, key=key, enabled=enabled, actor=f"admin:{claims.user_id}")


async def latest_health(claims: SessionClaims) -> list[health.HealthRow]:
    async with db_session(_ctx(claims)) as session:
        return await health.latest(session)


async def audit_log(claims: SessionClaims, limit: int) -> list[AuditView]:
    async with db_session(_ctx(claims)) as session:
        rows = await audit.list_recent(session, limit)
    return [AuditView(id=r.id, actor=r.actor, action=r.action, target=r.target, at=r.at) for r in rows]


async def active_kill_state(scan_id: uuid.UUID | None) -> kill.KillState:
    return await kill.state(get_redis(), scan_id)


async def set_active_kill(
    claims: SessionClaims, *, engaged: bool, scan_id: uuid.UUID | None
) -> kill.KillState:
    """ADR-0008 §3. Engage: the key is set before anything else. Release: the key is removed only
    after the audit row is committed. Both are audited (active.kill / active.unkill)."""
    redis = get_redis()
    target = "global" if scan_id is None else str(scan_id)
    if engaged:
        await kill.engage(redis, scan_id)
    async with db_session(_ctx(claims)) as session:
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="active.kill" if engaged else "active.unkill",
            target=target,
        )
    if not engaged:
        await kill.release(redis, scan_id)
    return kill.KillState(scope=target, engaged=engaged)


def ai() -> AIStatus:
    return ai_status(get_settings())
