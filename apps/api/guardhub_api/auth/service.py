"""Auth business logic: register, login, TOTP 2FA, logout, profile. Router-agnostic.

Every sensitive step is rate-limited and audited. Login lookups run under the narrow 'system' DB
context because the caller isn't authenticated yet; everything after login uses the user's own
RLS context.
"""

from __future__ import annotations

import time
import uuid

from redis.asyncio import Redis

from guardhub_api.auth import repository
from guardhub_api.auth.schemas import UserView
from guardhub_api.auth.security import (
    SessionClaims,
    hash_password,
    issue_session,
    new_totp_secret,
    password_problem,
    totp_matching_step,
    totp_uri,
    verify_password,
)
from guardhub_api.common import audit, ratelimit
from guardhub_api.common.crypto import Keyring, keyed_hash
from guardhub_api.common.errors import (
    ConflictError,
    NotFoundError,
    UnauthenticatedError,
    UnprocessableError,
)
from guardhub_api.common.request_meta import DEFAULT_LOCALE, match_locale
from guardhub_api.config import get_settings
from guardhub_api.db.models import User
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.platform import service as platform

LOGIN_WINDOW = 15 * 60


def user_view(user: User, *, mfa_complete: bool) -> UserView:
    return UserView(
        id=user.id,
        email=user.email,
        role="admin" if user.role == "admin" else "user",
        locale=user.locale,
        totp_enabled=user.totp_enabled,
        mfa_complete=mfa_complete,
        created_at=user.created_at,
    )


def _cipher() -> Keyring:
    return get_settings().keyring


def _pepper() -> str:
    return get_settings().hash_pepper.get_secret_value()


def pre_mfa_session(user: User) -> SessionClaims:
    return issue_session(
        user_id=user.id, role=user.role, mfa=False, ttl_seconds=get_settings().pre_mfa_ttl_seconds
    )


def full_session(user: User) -> SessionClaims:
    return issue_session(
        user_id=user.id, role=user.role, mfa=True, ttl_seconds=get_settings().session_ttl_seconds
    )


async def register(redis: Redis, *, email: str, password: str, locale: str, ip: str) -> User:
    await platform.require_feature("flags.registration")
    limit = await platform.int_value("rate.register_per_ip_hour")
    await ratelimit.enforce(redis, "register", keyed_hash(_pepper(), ip), limit=limit, window=3600)
    email = email.lower()
    problem = password_problem(password, email)
    if problem:
        raise UnprocessableError("weak_password", "Password does not meet the policy.", {"reason": problem})
    password_hash = await hash_password(password)
    async with db_session(DbContext.system()) as session:
        if await repository.by_email(session, email) is not None:
            raise ConflictError("email_taken", "An account with this email already exists.")
        user = await repository.add(
            session,
            User(
                email=email,
                password_hash=password_hash,
                role="user",
                locale=match_locale(locale) or DEFAULT_LOCALE,
            ),
        )
        await audit.record(session, actor=f"user:{user.id}", action="auth.register", target=str(user.id))
    return user


async def login(redis: Redis, *, email: str, password: str, ip: str) -> User:
    email = email.lower()
    ip_key = keyed_hash(_pepper(), ip)
    email_key = keyed_hash(_pepper(), email)
    await ratelimit.enforce(redis, "login-ip", ip_key, limit=30, window=LOGIN_WINDOW)
    await ratelimit.enforce(redis, "login-email", email_key, limit=10, window=LOGIN_WINDOW)
    async with db_session(DbContext.system()) as session:
        user = await repository.by_email(session, email)
        ok = await verify_password(user.password_hash if user else None, password)
        # The audit row commits with this transaction, so failures are recorded too.
        if ok and user is not None:
            await audit.record(
                session, actor=f"user:{user.id}", action="auth.password_ok", target=str(user.id)
            )
        else:
            await audit.record(
                session,
                actor="anonymous",
                action="auth.login_failed",
                target=str(user.id) if user else "unknown",
            )
    if not ok or user is None:
        raise UnauthenticatedError("invalid_credentials", "Email or password is incorrect.")
    return user


async def _load(user_id: uuid.UUID) -> User:
    async with db_session(DbContext.system()) as session:
        user = await repository.by_id(session, user_id)
    if user is None:
        raise UnauthenticatedError("session_invalid", "Session is no longer valid.")
    return user


async def setup_totp(claims: SessionClaims) -> tuple[str, str]:
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        user = await repository.by_id(session, claims.user_id)
        if user is None:
            raise UnauthenticatedError("session_invalid", "Session is no longer valid.")
        if user.totp_enabled:
            raise ConflictError("totp_already_enabled", "Two-factor authentication is already enabled.")
        secret = new_totp_secret()
        user.totp_secret = _cipher().encrypt(secret, associated_data=str(user.id).encode())
        await audit.record(
            session, actor=f"user:{user.id}", action="auth.totp_setup_started", target=str(user.id)
        )
        return secret, totp_uri(secret, user.email)


async def verify_totp(redis: Redis, claims: SessionClaims, code: str) -> User:
    await ratelimit.enforce(redis, "totp", str(claims.user_id), limit=5, window=300)
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        user = await repository.by_id(session, claims.user_id)
        if user is None:
            raise UnauthenticatedError("session_invalid", "Session is no longer valid.")
        if not user.totp_secret:
            raise UnprocessableError("totp_not_setup", "Set up two-factor authentication first.")
        secret = _cipher().decrypt(user.totp_secret, associated_data=str(user.id).encode())
        step = totp_matching_step(secret, code)
        replay_key = f"gh:totp:last:{user.id}"
        last = await redis.get(replay_key)
        accepted = step is not None and (last is None or step > int(last))
        if accepted and step is not None:
            await redis.set(replay_key, str(step), ex=300)
            if not user.totp_enabled:
                user.totp_enabled = True
                await audit.record(
                    session, actor=f"user:{user.id}", action="auth.totp_enabled", target=str(user.id)
                )
            await audit.record(session, actor=f"user:{user.id}", action="auth.login", target=str(user.id))
        else:
            await audit.record(
                session, actor=f"user:{user.id}", action="auth.totp_failed", target=str(user.id)
            )
    if not accepted:
        raise UnauthenticatedError("invalid_totp", "The code is not valid.")
    return user


async def revoke(redis: Redis, claims: SessionClaims) -> None:
    ttl = max(1, claims.exp - int(time.time()))
    await redis.set(f"gh:session:revoked:{claims.jti}", "1", ex=ttl)


async def is_revoked(redis: Redis, jti: str) -> bool:
    return bool(await redis.exists(f"gh:session:revoked:{jti}"))


async def logout(redis: Redis, claims: SessionClaims) -> None:
    await revoke(redis, claims)
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        await audit.record(
            session, actor=f"user:{claims.user_id}", action="auth.logout", target=str(claims.user_id)
        )


async def get_user(claims: SessionClaims) -> User:
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        user = await repository.by_id(session, claims.user_id)
    if user is None:
        raise NotFoundError("user_not_found", "User not found.")
    return user


async def update_locale(claims: SessionClaims, locale: str) -> User:
    matched = match_locale(locale)
    if matched is None:
        raise UnprocessableError("unsupported_locale", "Unsupported language.")
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        user = await repository.by_id(session, claims.user_id)
        if user is None:
            raise NotFoundError("user_not_found", "User not found.")
        user.locale = matched
        return user


async def current_role(user_id: uuid.UUID) -> str:
    """The role from the database (not the token), for authorisation decisions."""
    return (await _load(user_id)).role
