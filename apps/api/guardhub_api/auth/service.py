"""Auth business logic: register, login, TOTP 2FA, logout, profile. Router-agnostic.

Every sensitive step is rate-limited and audited. Login lookups run under the narrow 'system' DB
context because the caller isn't authenticated yet; everything after login uses the user's own
RLS context.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis

from guardhub_api.auth import recovery, repository
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
    ForbiddenError,
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
        display_name=user.display_name,
        totp_enabled=user.totp_enabled,
        mfa_complete=mfa_complete,
        created_at=user.created_at,
        password_changed_at=user.password_changed_at,
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
    if user.disabled_at is not None:  # only after the right password: no account probing
        raise ForbiddenError("account_disabled", "This account is disabled.")
    return user


async def _load(user_id: uuid.UUID) -> User:
    async with db_session(DbContext.system()) as session:
        user = await repository.by_id(session, user_id)
    if user is None or user.disabled_at is not None:
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


async def verify_totp(redis: Redis, claims: SessionClaims, code: str) -> tuple[User, list[str] | None]:
    """The user, and their first recovery codes when this code just enabled two-factor."""
    codes: list[str] | None = None
    await ratelimit.enforce(redis, "totp", str(claims.user_id), limit=5, window=300)
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        user = await repository.by_id(session, claims.user_id)
        if user is None or user.disabled_at is not None:
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
                codes = await recovery.generate(session, user.id)  # shown once, right now
                await audit.record(
                    session, actor=f"user:{user.id}", action="auth.totp_enabled", target=str(user.id)
                )
            user.last_login_at = datetime.now(UTC)
            await audit.record(session, actor=f"user:{user.id}", action="auth.login", target=str(user.id))
        else:
            await audit.record(
                session, actor=f"user:{user.id}", action="auth.totp_failed", target=str(user.id)
            )
    if not accepted:
        raise UnauthenticatedError("invalid_totp", "The code is not valid.")
    return user, codes


async def recover(redis: Redis, claims: SessionClaims, code: str) -> User:
    """Sign-in with a recovery code instead of the authenticator code (once per code)."""
    await ratelimit.enforce(redis, "totp", str(claims.user_id), limit=5, window=300)
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        user = await repository.by_id(session, claims.user_id)
        if user is None or user.disabled_at is not None:
            raise UnauthenticatedError("session_invalid", "Session is no longer valid.")
        if not user.totp_enabled:
            raise UnprocessableError("totp_not_setup", "Set up two-factor authentication first.")
        ok = await recovery.consume(session, user.id, code)
        if ok:
            user.last_login_at = datetime.now(UTC)
            left = await recovery.remaining(session, user.id)
            await audit.record(
                session,
                actor=f"user:{user.id}",
                action="auth.recovery_code_used",
                target=str(user.id),
                metadata={"remaining": str(left)},
            )
        else:
            await audit.record(
                session,
                actor=f"user:{user.id}",
                action="auth.totp_failed",
                target=str(user.id),
                metadata={"via": "recovery_code"},
            )
    if not ok:
        raise UnauthenticatedError("invalid_recovery_code", "This recovery code is not valid.")
    return user


async def recovery_status(claims: SessionClaims) -> int:
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        return await recovery.remaining(session, claims.user_id)


async def regenerate_recovery_codes(redis: Redis, claims: SessionClaims, code: str) -> list[str]:
    """New codes for a signed-in account that proves a current authenticator code."""
    await ratelimit.enforce(redis, "totp", str(claims.user_id), limit=5, window=300)
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        user = await repository.by_id(session, claims.user_id)
        if user is None or not user.totp_secret or not user.totp_enabled:
            raise UnprocessableError("totp_not_setup", "Set up two-factor authentication first.")
        secret = _cipher().decrypt(user.totp_secret, associated_data=str(user.id).encode())
        if not await recovery.current_code_ok(redis, user, code, secret):
            await audit.record(
                session,
                actor=f"user:{user.id}",
                action="auth.totp_failed",
                target=str(user.id),
                metadata={"via": "recovery_regenerate"},
            )
            ok = False
        else:
            codes = await recovery.generate(session, user.id)
            await audit.record(
                session,
                actor=f"user:{user.id}",
                action="auth.recovery_codes_regenerated",
                target=str(user.id),
            )
            ok = True
    if not ok:
        raise UnauthenticatedError("invalid_totp", "The code is not valid.")
    return codes


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


async def update_profile(claims: SessionClaims, *, locale: str | None, display_name: str | None) -> User:
    """The account holder's own profile: language and display name. Nothing here grants access."""
    matched = None
    if locale is not None:
        matched = match_locale(locale)
        if matched is None:
            raise UnprocessableError("unsupported_locale", "Unsupported language.")
    name: str | None = None
    if display_name is not None:
        name = " ".join(display_name.split())  # collapse runs of whitespace
        if any(not ch.isprintable() for ch in name):
            raise UnprocessableError(
                "invalid_display_name", "The name contains characters that are not allowed."
            )
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        user = await repository.by_id(session, claims.user_id)
        if user is None:
            raise NotFoundError("user_not_found", "User not found.")
        if matched is not None:
            user.locale = matched
        if display_name is not None and (name or None) != user.display_name:
            user.display_name = name or None
            await audit.record(
                session,
                actor=f"user:{user.id}",
                action="auth.profile_updated",
                target=str(user.id),
                metadata={"field": "display_name"},
            )
        return user


async def change_password(
    redis: Redis, claims: SessionClaims, *, current_password: str, new_password: str, code: str
) -> User:
    """Change one's own password: the current password AND a current authenticator code (step-up),
    rate-limited and audited (failures too). The caller ends the account's other sessions."""
    await ratelimit.enforce(redis, "password-change", str(claims.user_id), limit=5, window=LOGIN_WINDOW)
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        user = await repository.by_id(session, claims.user_id)
        if user is None or user.disabled_at is not None:
            raise UnauthenticatedError("session_invalid", "Session is no longer valid.")
        reason: str | None = None
        if not await verify_password(user.password_hash, current_password):
            reason = "wrong_password"
        elif not user.totp_enabled or not user.totp_secret:
            reason = "totp_not_setup"
        else:
            secret = _cipher().decrypt(user.totp_secret, associated_data=str(user.id).encode())
            if not await recovery.current_code_ok(redis, user, code, secret):
                reason = "invalid_totp"
        problem = None if reason else password_problem(new_password, user.email)
        if reason is None and problem is None and new_password == current_password:
            problem = "same_as_current"
        failed = reason or problem
        if not failed:
            user.password_hash = await hash_password(new_password)
            user.password_changed_at = datetime.now(UTC)
        await audit.record(
            session,
            actor=f"user:{user.id}",
            action="auth.password_change_failed" if failed else "auth.password_changed",
            target=str(user.id),
            metadata={"reason": failed} if failed else None,
        )
    if reason == "wrong_password":
        raise UnauthenticatedError("wrong_current_password", "The current password is incorrect.")
    if reason == "totp_not_setup":
        raise UnprocessableError("totp_not_setup", "Set up two-factor authentication first.")
    if reason == "invalid_totp":
        raise UnauthenticatedError("invalid_totp", "The code is not valid.")
    if problem:
        raise UnprocessableError("weak_password", "Password does not meet the policy.", {"reason": problem})
    return user


async def current_role(user_id: uuid.UUID) -> str:
    """The role from the database (not the token), for authorisation decisions."""
    return (await _load(user_id)).role
