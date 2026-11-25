"""Integration API keys (Admin Panel, Prompt 2 §4).

A key is `ghk_` + 32 random bytes, shown once at creation; only its keyed hash (pepper) is
stored, plus a 12-character prefix to recognise it. Scopes: projects:read, scans:read,
scans:trigger. Expiry is required (at most 365 days) and a key can be revoked at any time.

Boundaries, by construction:
- a key never produces a session: the admin API and every cookie-session route ignore it;
- a key acts as its owner in the **user** database role (RLS), even when the owner is an admin;
- a triggered scan goes through `start_project_scan`, which re-checks ownership proof (§9.2);
- 120 requests per minute per key; every key change and every triggered scan is audited.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal

from fastapi import Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select

from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit, ratelimit
from guardhub_api.common.crypto import keyed_hash, random_token
from guardhub_api.common.errors import ForbiddenError, NotFoundError, UnauthenticatedError, UnprocessableError
from guardhub_api.common.redis import get_redis
from guardhub_api.config import get_settings
from guardhub_api.db.models import ApiKey, User
from guardhub_api.db.session import DbContext, db_session

Scope = Literal["projects:read", "scans:read", "scans:trigger"]
SCOPES: tuple[Scope, ...] = ("projects:read", "scans:read", "scans:trigger")
EXPIRY_DAYS = (30, 90, 180, 365)
PER_MINUTE = 120
_KEY_RE = re.compile(r"^ghk_[A-Za-z0-9_-]{43}$")
_TOUCH_GATE = "gh:apikey:touched:"


def _hash(key: str) -> str:
    return keyed_hash(get_settings().hash_pepper.get_secret_value(), key)


# ---- the admin's screen ----


class CreateKeyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    scopes: list[Scope] = Field(min_length=1, max_length=len(SCOPES))
    expires_in_days: int


class KeyView(BaseModel):
    id: uuid.UUID
    name: str
    prefix: str
    owner_email: str | None
    scopes: list[str]
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None
    status: Literal["active", "expired", "revoked"]


class CreatedKey(BaseModel):
    key: KeyView
    secret: str  # shown once, never stored or returned again


def _status(k: ApiKey, now: datetime) -> Literal["active", "expired", "revoked"]:
    if k.revoked_at is not None:
        return "revoked"
    return "expired" if k.expires_at <= now else "active"


def _view(k: ApiKey, email: str | None, now: datetime) -> KeyView:
    return KeyView(
        id=k.id,
        name=k.name,
        prefix=k.prefix,
        owner_email=email,
        scopes=list(k.scopes),
        created_at=k.created_at,
        expires_at=k.expires_at,
        last_used_at=k.last_used_at,
        revoked_at=k.revoked_at,
        status=_status(k, now),
    )


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="admin", user_id=claims.user_id)


async def list_keys(claims: SessionClaims) -> list[KeyView]:
    now = datetime.now(UTC)
    async with db_session(_ctx(claims)) as session:
        rows = (
            await session.execute(
                select(ApiKey, User.email)
                .join(User, User.id == ApiKey.user_id)
                .order_by(ApiKey.created_at.desc())
            )
        ).all()
    return [_view(k, email, now) for k, email in rows]


async def create_key(claims: SessionClaims, body: CreateKeyRequest) -> CreatedKey:
    if body.expires_in_days not in EXPIRY_DAYS:
        raise UnprocessableError("api_key_expiry_invalid", "Choose 30, 90, 180 or 365 days.")
    name = body.name.strip()
    if not name or any(ord(c) < 32 for c in name):
        raise UnprocessableError("api_key_name_invalid", "Give the key a short name.")
    secret = random_token("ghk", 32)
    now = datetime.now(UTC)
    async with db_session(_ctx(claims)) as session:
        key = ApiKey(
            user_id=claims.user_id,
            name=name,
            prefix=secret[:12],
            key_hash=_hash(secret),
            scopes=sorted(set(body.scopes)),
            expires_at=now + timedelta(days=body.expires_in_days),
            created_at=now,
        )
        session.add(key)
        await session.flush()
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="api_key.created",
            target=str(key.id),
            metadata={
                "prefix": key.prefix,
                "scopes": ",".join(key.scopes),
                "days": str(body.expires_in_days),
            },
        )
        email = (
            await session.execute(select(User.email).where(User.id == claims.user_id))
        ).scalar_one_or_none()
        return CreatedKey(key=_view(key, email, now), secret=secret)


async def revoke_key(claims: SessionClaims, key_id: uuid.UUID) -> KeyView:
    now = datetime.now(UTC)
    async with db_session(_ctx(claims)) as session:
        key = await session.get(ApiKey, key_id, with_for_update=True)
        if key is None:
            raise NotFoundError("api_key_not_found", "This API key does not exist.")
        if key.revoked_at is None:
            key.revoked_at, key.revoked_by = now, claims.user_id
            await audit.record(
                session,
                actor=f"admin:{claims.user_id}",
                action="api_key.revoked",
                target=str(key.id),
                metadata={"prefix": key.prefix},
            )
        email = (await session.execute(select(User.email).where(User.id == key.user_id))).scalar_one_or_none()
        await session.flush()
        return _view(key, email, now)


# ---- authenticating a request ----


@dataclass(frozen=True, slots=True)
class KeyPrincipal:
    key_id: uuid.UUID
    owner_id: uuid.UUID
    scopes: frozenset[str]

    @property
    def ctx(self) -> DbContext:
        return DbContext(role="user", user_id=self.owner_id)  # never admin, whatever the owner is

    @property
    def actor(self) -> str:
        return f"apikey:{self.key_id}"

    def require(self, scope: Scope) -> None:
        if scope not in self.scopes:
            raise ForbiddenError("api_key_scope_missing", f"This API key lacks the {scope} scope.")


async def api_key_principal(request: Request) -> KeyPrincipal:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not _KEY_RE.fullmatch(token):
        raise UnauthenticatedError("api_key_missing", "Send an API key: Authorization: Bearer ghk_...")
    now = datetime.now(UTC)
    async with db_session(DbContext.system()) as session:
        key = (
            await session.execute(select(ApiKey).where(ApiKey.key_hash == _hash(token)))
        ).scalar_one_or_none()
        if key is None or key.revoked_at is not None or key.expires_at <= now:
            raise UnauthenticatedError("api_key_invalid", "This API key is unknown, expired or revoked.")
        principal = KeyPrincipal(key_id=key.id, owner_id=key.user_id, scopes=frozenset(key.scopes))
    redis = get_redis()
    await ratelimit.enforce(redis, "api-key", str(principal.key_id), limit=PER_MINUTE, window=60)
    if await redis.set(f"{_TOUCH_GATE}{principal.key_id}", "1", nx=True, ex=60):
        async with db_session(DbContext.system()) as session:
            row = await session.get(ApiKey, principal.key_id)
            if row is not None:
                row.last_used_at = now
    return principal


ApiKeyPrincipal = Annotated[KeyPrincipal, Depends(api_key_principal)]
