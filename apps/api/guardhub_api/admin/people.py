"""Users & sessions, simple (Admin Panel, Prompt 2 §5). Not a role matrix (RBAC is deferred):
there are customers and admins, and the data boundary stays in the database (RLS).

- Disable / enable an account. Disabling ends every session at once, stops sign-in and the
  account's API keys. An admin can never disable themselves or the last active admin.
- See and end an account's sessions (one or all).
- Failed sign-ins: password and two-factor failures from the audit log, with the keyed IP hash.
- Admin invitations: a one-time link (72 h, bound to one e-mail, hash stored). It makes an
  account an admin only when that exact e-mail is signed in with two-factor and accepts it.
Every action is audited.
"""

from __future__ import annotations

import contextlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Query, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.auth import service as auth_service
from guardhub_api.auth import sessions
from guardhub_api.auth.deps import AdminSession, FullSession, set_session_cookie
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit
from guardhub_api.common.crypto import keyed_hash, random_token
from guardhub_api.common.errors import ConflictError, ForbiddenError, NotFoundError, UnprocessableError
from guardhub_api.common.redis import get_redis
from guardhub_api.common.request_meta import client_ip
from guardhub_api.config import get_settings
from guardhub_api.db.models import AdminInvite, AuditLog, User
from guardhub_api.db.session import DbContext, db_session

router = APIRouter(prefix="/admin/people", tags=["admin"])
accept_router = APIRouter(prefix="/auth/admin-invite", tags=["auth"])
INVITE_HOURS = 72
FAILED_ACTIONS = ("auth.login_failed", "auth.totp_failed")


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="admin", user_id=claims.user_id)


def _hash(token: str) -> str:
    return keyed_hash(get_settings().hash_pepper.get_secret_value(), token)


def _actor(claims: SessionClaims) -> str:
    return f"admin:{claims.user_id}"


# ---- accounts ----


class AccountState(BaseModel):
    id: uuid.UUID
    disabled_at: datetime | None
    sessions_ended: int = 0


class DisableRequest(BaseModel):
    reason: str = Field(default="", max_length=200)


async def _active_admins(session: AsyncSession) -> int:
    stmt = select(func.count()).select_from(User).where(User.role == "admin", User.disabled_at.is_(None))
    return int((await session.execute(stmt)).scalar_one())


@router.post("/{user_id}/disable")
async def disable(user_id: uuid.UUID, body: DisableRequest, claims: AdminSession) -> AccountState:
    if user_id == claims.user_id:
        raise UnprocessableError("cannot_disable_self", "You cannot disable your own account.")
    async with db_session(_ctx(claims)) as session:
        user = await session.get(User, user_id, with_for_update=True)
        if user is None:
            raise NotFoundError("user_not_found", "User not found.")
        if user.disabled_at is None:
            if user.role == "admin" and await _active_admins(session) <= 1:
                raise UnprocessableError("last_admin", "The last active admin cannot be disabled.")
            user.disabled_at, user.disabled_by = datetime.now(UTC), claims.user_id
            await audit.record(
                session,
                actor=_actor(claims),
                action="user.disabled",
                target=str(user.id),
                metadata={"reason": body.reason.strip()[:200], "role": user.role},
            )
        disabled_at = user.disabled_at
    ended = await sessions.end(get_redis(), user_id)
    return AccountState(id=user_id, disabled_at=disabled_at, sessions_ended=ended)


@router.post("/{user_id}/enable")
async def enable(user_id: uuid.UUID, claims: AdminSession) -> AccountState:
    async with db_session(_ctx(claims)) as session:
        user = await session.get(User, user_id, with_for_update=True)
        if user is None:
            raise NotFoundError("user_not_found", "User not found.")
        if user.disabled_at is not None:
            user.disabled_at, user.disabled_by = None, None
            await audit.record(session, actor=_actor(claims), action="user.enabled", target=str(user.id))
    return AccountState(id=user_id, disabled_at=None)


# ---- sessions ----


class EndSessionsRequest(BaseModel):
    jti: str | None = Field(default=None, max_length=64)  # None: all sessions


async def _existing(claims: SessionClaims, user_id: uuid.UUID) -> None:
    async with db_session(_ctx(claims)) as session:
        if await session.get(User, user_id) is None:
            raise NotFoundError("user_not_found", "User not found.")


@router.get("/{user_id}/sessions")
async def list_sessions(user_id: uuid.UUID, claims: AdminSession) -> list[sessions.SessionView]:
    await _existing(claims, user_id)
    return await sessions.list_sessions(get_redis(), user_id)


@router.post("/{user_id}/sessions/end")
async def end_sessions(user_id: uuid.UUID, body: EndSessionsRequest, claims: AdminSession) -> AccountState:
    await _existing(claims, user_id)
    ended = await sessions.end(get_redis(), user_id, body.jti)
    async with db_session(_ctx(claims)) as session:
        await audit.record(
            session,
            actor=_actor(claims),
            action="user.sessions_ended",
            target=str(user_id),
            metadata={"count": str(ended), "scope": "one" if body.jti else "all"},
        )
        user = await session.get(User, user_id)
        return AccountState(id=user_id, disabled_at=user.disabled_at if user else None, sessions_ended=ended)


# ---- failed sign-ins ----


class FailedSignIn(BaseModel):
    at: datetime
    kind: Literal["password", "two_factor"]
    account: str | None  # the account's e-mail when it exists, else None (unknown address)
    ip_hash: str


class FailedSignIns(BaseModel):
    hours: int
    total: int
    by_account: dict[str, int]
    recent: list[FailedSignIn]


@router.get("/security/failed-sign-ins")
async def failed_sign_ins(claims: AdminSession, hours: int = Query(default=24)) -> FailedSignIns:
    if hours not in (1, 24, 168):  # an int query: a Literal of ints rejects "24" from the URL
        raise UnprocessableError("failed_sign_ins_hours_invalid", "Choose 1, 24 or 168 hours.")
    since = datetime.now(UTC) - timedelta(hours=hours)
    async with db_session(_ctx(claims)) as session:
        rows = (
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.action.in_(FAILED_ACTIONS), AuditLog.at >= since)
                    .order_by(AuditLog.at.desc())
                    .limit(2000)
                )
            )
            .scalars()
            .all()
        )
        ids = set()
        for r in rows:
            with contextlib.suppress(ValueError):  # "unknown" for an address with no account
                ids.add(uuid.UUID(r.target))
        emails = (
            dict((await session.execute(select(User.id, User.email).where(User.id.in_(ids)))).all())
            if ids
            else {}
        )
    recent: list[FailedSignIn] = []
    counts: dict[str, int] = {}
    for r in rows:
        try:
            account = emails.get(uuid.UUID(r.target))
        except ValueError:
            account = None
        name = account or "unknown"
        counts[name] = counts.get(name, 0) + 1
        if len(recent) < 100:
            recent.append(
                FailedSignIn(
                    at=r.at,
                    kind="password" if r.action == "auth.login_failed" else "two_factor",
                    account=account,
                    ip_hash=str(r.metadata_.get("ip_hash", "")),
                )
            )
    top = dict(sorted(counts.items(), key=lambda kv: -kv[1])[:20])
    return FailedSignIns(hours=hours, total=len(rows), by_account=top, recent=recent)


# ---- admin invitations ----


class InviteRequest(BaseModel):
    email: EmailStr


class InviteView(BaseModel):
    id: uuid.UUID
    email: str
    created_at: datetime
    expires_at: datetime
    status: Literal["pending", "accepted", "expired", "revoked"]


class CreatedInvite(BaseModel):
    invite: InviteView
    link: str  # shown once


def _invite_view(i: AdminInvite, now: datetime) -> InviteView:
    status: Literal["pending", "accepted", "expired", "revoked"] = (
        "accepted"
        if i.accepted_at
        else "revoked"
        if i.revoked_at
        else "expired"
        if i.expires_at <= now
        else "pending"
    )
    return InviteView(id=i.id, email=i.email, created_at=i.created_at, expires_at=i.expires_at, status=status)


@router.get("/invites")
async def list_invites(claims: AdminSession) -> list[InviteView]:
    now = datetime.now(UTC)
    async with db_session(_ctx(claims)) as session:
        rows = (
            await session.execute(select(AdminInvite).order_by(AdminInvite.created_at.desc()).limit(50))
        ).scalars()
        return [_invite_view(i, now) for i in rows.all()]


@router.post("/invites", status_code=201)
async def create_invite(body: InviteRequest, claims: AdminSession) -> CreatedInvite:
    email = str(body.email).lower()
    token = random_token("ghi", 32)
    now = datetime.now(UTC)
    async with db_session(_ctx(claims)) as session:
        existing = (await session.execute(select(User.role).where(User.email == email))).scalar()
        if existing == "admin":
            raise ConflictError("already_admin", "This account is already an admin.")
        invite = AdminInvite(
            email=email,
            token_hash=_hash(token),
            invited_by=claims.user_id,
            created_at=now,
            expires_at=now + timedelta(hours=INVITE_HOURS),
        )
        session.add(invite)
        await session.flush()
        await audit.record(
            session,
            actor=_actor(claims),
            action="admin_invite.created",
            target=str(invite.id),
            metadata={"email": email},
        )
        view = _invite_view(invite, now)
    link = f"{get_settings().public_base_url.rstrip('/')}/account/admin-invite?token={token}"
    return CreatedInvite(invite=view, link=link)


@router.post("/invites/{invite_id}/revoke")
async def revoke_invite(invite_id: uuid.UUID, claims: AdminSession) -> InviteView:
    now = datetime.now(UTC)
    async with db_session(_ctx(claims)) as session:
        invite = await session.get(AdminInvite, invite_id, with_for_update=True)
        if invite is None:
            raise NotFoundError("invite_not_found", "This invitation does not exist.")
        if invite.accepted_at is None and invite.revoked_at is None:
            invite.revoked_at = now
            await audit.record(
                session, actor=_actor(claims), action="admin_invite.revoked", target=str(invite.id)
            )
        return _invite_view(invite, now)


class AcceptRequest(BaseModel):
    token: str = Field(min_length=10, max_length=100)


class Accepted(BaseModel):
    role: Literal["admin"]


@accept_router.post("/accept")
async def accept_invite(
    body: AcceptRequest, claims: FullSession, request: Request, response: Response
) -> Accepted:
    """The invited person, signed in with two-factor as exactly the invited e-mail, becomes an admin."""
    now = datetime.now(UTC)
    async with db_session(DbContext.system()) as session:
        invite = (
            await session.execute(
                select(AdminInvite).where(AdminInvite.token_hash == _hash(body.token)).with_for_update()
            )
        ).scalar_one_or_none()
        user = await session.get(User, claims.user_id, with_for_update=True)
        valid = (
            invite is not None
            and invite.accepted_at is None
            and invite.revoked_at is None
            and invite.expires_at > now
        )
        if not valid or user is None or invite is None:
            raise NotFoundError("invite_invalid", "This invitation is unknown, used, revoked or expired.")
        if user.email != invite.email:
            raise ForbiddenError("invite_wrong_account", "Sign in with the invited e-mail address to accept.")
        if not (claims.mfa and user.totp_enabled) or user.disabled_at is not None:
            raise ForbiddenError("mfa_required", "Complete two-factor authentication first.")
        invite.accepted_at, invite.accepted_by = now, user.id
        previous, user.role = user.role, "admin"
        await audit.record(
            session, actor=f"user:{user.id}", action="admin_invite.accepted", target=str(invite.id)
        )
        await audit.record(
            session,
            actor=f"user:{user.id}",
            action="user.role_changed",
            target=str(user.id),
            metadata={"from": previous, "to": "admin", "via": "invite"},
        )
        fresh_user = user
    redis = get_redis()
    await auth_service.revoke(redis, claims)  # the old session carried the old role
    fresh = auth_service.full_session(fresh_user)
    set_session_cookie(response, fresh)
    await sessions.forget(redis, claims.user_id, claims.jti)
    await sessions.record(
        redis,
        fresh,
        ip_hash=keyed_hash(get_settings().hash_pepper.get_secret_value(), client_ip(request)),
        user_agent=request.headers.get("user-agent", ""),
    )
    return Accepted(role="admin")
