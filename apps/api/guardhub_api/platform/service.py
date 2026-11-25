"""Runtime settings (Admin Panel, Prompt 2 §1): read the effective value of a tunable, and the
admin's configuration screen (view, change, reset to default, revert a past change).

Reads are cached per process for a few seconds, so a change reaches every API and worker
process within CACHE_SECONDS. Every change is audited (config.changed / config.reset /
config.reverted) with the old and new value; that audit trail is the history the admin reverts
from. The environment is shown read-only and secrets only as "configured" or "not set".
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, SecretStr
from sqlalchemy import select

from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit
from guardhub_api.common.errors import NotFoundError, ServiceUnavailableError, UnprocessableError
from guardhub_api.config import Settings, get_settings
from guardhub_api.db.models import AuditLog, PlatformSetting, User
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.platform.registry import BY_KEY, TUNABLES, InvalidValueError, Tunable, coerce

CACHE_SECONDS = 5.0
HISTORY_LIMIT = 50
DEFAULT_MARK = "__default__"  # audit metadata: "no override" (the default applied)
CONFIG_ACTIONS = ("config.changed", "config.reset", "config.reverted")

# Environment values safe to show as they are (no credentials, no private infrastructure detail).
VISIBLE_ENV = frozenset(
    {
        "public_base_url",
        "cookie_secure",
        "trusted_proxy_hops",
        "log_level",
        "active_testing_approved",
        "session_ttl_seconds",
        "pre_mfa_ttl_seconds",
        "scan_deadline_seconds",
        "verify_timeout_seconds",
        "challenge_ttl_hours",
        "scheduler_batch",
        "scheduler_max_inflight",
        "smtp_port",
        "smtp_security",
        "smtp_timeout_seconds",
        "sentry_api_url",
        "github_api_url",
        "github_web_url",
    }
)

_cache: dict[str, tuple[float, object]] = {}


def clear_cache() -> None:
    _cache.clear()


async def _load_overrides() -> dict[str, object]:
    async with db_session(DbContext.system()) as session:
        rows = (await session.execute(select(PlatformSetting))).scalars().all()
        return {r.key: r.value for r in rows}


async def value(key: str) -> int | bool | str:
    """The effective value: the admin's override if it is still valid, else the default."""
    t = BY_KEY[key]
    hit = _cache.get(key)
    now = time.monotonic()
    if hit is None or hit[0] < now:
        overrides = await _load_overrides()
        for k in BY_KEY:
            _cache[k] = (now + CACHE_SECONDS, overrides.get(k, DEFAULT_MARK))
        hit = _cache[key]
    stored = hit[1]
    if stored == DEFAULT_MARK:
        return t.default()
    try:
        return coerce(t, stored)
    except InvalidValueError:  # a bound tightened in a later release: fall back, never use it
        return t.default()


async def int_value(key: str) -> int:
    v = await value(key)
    assert isinstance(v, int) and not isinstance(v, bool)
    return v


async def flag(key: str) -> bool:
    v = await value(key)
    assert isinstance(v, bool)
    return v


async def require_no_maintenance() -> None:
    """503 `maintenance` while maintenance mode is on: no new scans of any kind but owner tests."""
    if await flag("maintenance.enabled"):
        message = str(await value("maintenance.message"))
        raise ServiceUnavailableError(
            "maintenance",
            "GuardHub is in maintenance. New scans are paused for a short while.",
            {"message": message} if message else None,
        )


async def require_feature(feature: Literal["flags.public_scan", "flags.registration"]) -> None:
    """503 while `feature` is switched off by an admin."""
    if feature == "flags.public_scan" and not await flag(feature):
        raise ServiceUnavailableError("public_scan_paused", "Scans without an account are paused for now.")
    if feature == "flags.registration" and not await flag(feature):
        raise ServiceUnavailableError("registration_closed", "New sign-ups are closed for now.")


# ---- the admin's screen ----


class SettingView(BaseModel):
    key: str
    group: str
    kind: str
    value: int | bool | str
    default: int | bool | str
    overridden: bool
    minimum: int | None
    maximum: int | None
    max_length: int | None
    updated_at: datetime | None
    updated_by: str | None


class EnvView(BaseModel):
    name: str
    kind: Literal["value", "secret", "hidden"]
    configured: bool
    value: str | None  # only for kind == "value"


class ChangeView(BaseModel):
    id: int
    at: datetime
    action: str
    actor: str
    actor_email: str | None
    key: str
    old: str
    new: str
    reason: str
    revertible: bool


class ConfigView(BaseModel):
    settings: list[SettingView]
    environment: list[EnvView]
    history: list[ChangeView]
    cache_seconds: float


class PlatformStatus(BaseModel):
    """What the public site needs to know (no auth): a maintenance banner and closed features."""

    maintenance: bool
    message: str
    public_scan: bool
    registration: bool


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="admin", user_id=claims.user_id)


def _dump(v: object) -> str:
    return DEFAULT_MARK if v == DEFAULT_MARK else json.dumps(v)


def environment(settings: Settings | None = None) -> list[EnvView]:
    s = settings or get_settings()
    out: list[EnvView] = []
    for name in sorted(type(s).model_fields):
        v = getattr(s, name)
        if isinstance(v, SecretStr):
            out.append(EnvView(name=name, kind="secret", configured=bool(v.get_secret_value()), value=None))
        elif name in VISIBLE_ENV:
            out.append(EnvView(name=name, kind="value", configured=v not in ("", None), value=str(v)))
        else:
            out.append(EnvView(name=name, kind="hidden", configured=v not in ("", None), value=None))
    return out


async def status() -> PlatformStatus:
    return PlatformStatus(
        maintenance=await flag("maintenance.enabled"),
        message=str(await value("maintenance.message")),
        public_scan=await flag("flags.public_scan"),
        registration=await flag("flags.registration"),
    )


async def view(claims: SessionClaims) -> ConfigView:
    async with db_session(_ctx(claims)) as session:
        rows = {r.key: r for r in (await session.execute(select(PlatformSetting))).scalars().all()}
        audit_rows = (
            (
                await session.execute(
                    select(AuditLog)
                    .where(AuditLog.action.in_(CONFIG_ACTIONS))
                    .order_by(AuditLog.at.desc(), AuditLog.id.desc())
                    .limit(HISTORY_LIMIT)
                )
            )
            .scalars()
            .all()
        )
        ids = {_actor_id(a.actor) for a in audit_rows} | {r.updated_by for r in rows.values()}
        ids.discard(None)
        emails = (
            {
                u.id: u.email
                for u in (await session.execute(select(User).where(User.id.in_(ids)))).scalars().all()
            }
            if ids
            else {}
        )
    settings: list[SettingView] = []
    for t in TUNABLES:
        row = rows.get(t.key)
        effective: int | bool | str = t.default()
        if row is not None:
            try:
                effective = coerce(t, row.value)
            except InvalidValueError:
                row = None
        settings.append(
            SettingView(
                key=t.key,
                group=t.group,
                kind=t.kind,
                value=effective,
                default=t.default(),
                overridden=row is not None,
                minimum=t.minimum,
                maximum=t.maximum,
                max_length=t.max_length,
                updated_at=row.updated_at if row else None,
                updated_by=emails.get(row.updated_by) if row and row.updated_by else None,
            )
        )
    history = [
        ChangeView(
            id=a.id,
            at=a.at,
            action=a.action,
            actor=a.actor,
            actor_email=_email(emails, _actor_id(a.actor)),
            key=a.metadata_.get("key", ""),
            old=a.metadata_.get("old", ""),
            new=a.metadata_.get("new", ""),
            reason=a.metadata_.get("reason", ""),
            revertible=a.metadata_.get("key", "") in BY_KEY,
        )
        for a in audit_rows
    ]
    return ConfigView(
        settings=settings, environment=environment(), history=history, cache_seconds=CACHE_SECONDS
    )


def _email(emails: dict[uuid.UUID, str], user_id: uuid.UUID | None) -> str | None:
    return emails.get(user_id) if user_id is not None else None


def _actor_id(actor: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(actor.removeprefix("admin:"))
    except ValueError:
        return None


def _tunable(key: str) -> Tunable:
    t = BY_KEY.get(key)
    if t is None:
        raise NotFoundError("setting_unknown", "This setting does not exist or cannot be changed here.")
    return t


async def _apply(
    claims: SessionClaims, *, key: str, new: object, action: str, reason: str, extra: dict[str, str]
) -> None:
    """Store `new` (DEFAULT_MARK = remove the override) and audit old -> new, in one transaction."""
    async with db_session(_ctx(claims)) as session:
        row = await session.get(PlatformSetting, key, with_for_update=True)
        old: object = row.value if row is not None else DEFAULT_MARK
        if new == DEFAULT_MARK:
            if row is not None:
                await session.delete(row)
        elif row is None:
            session.add(
                PlatformSetting(key=key, value=new, updated_by=claims.user_id, updated_at=datetime.now(UTC))
            )
        else:
            row.value, row.updated_by, row.updated_at = new, claims.user_id, datetime.now(UTC)
        await session.flush()
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action=action,
            target=key,
            metadata={"key": key, "old": _dump(old), "new": _dump(new), "reason": reason[:200], **extra},
        )
    clear_cache()


async def set_value(claims: SessionClaims, key: str, raw: object, reason: str = "") -> SettingView:
    t = _tunable(key)
    try:
        new = coerce(t, raw)
    except InvalidValueError as exc:
        raise UnprocessableError("setting_invalid", str(exc), {"key": key}) from exc
    await _apply(claims, key=key, new=new, action="config.changed", reason=reason, extra={})
    return await _one(claims, key)


async def reset(claims: SessionClaims, key: str, reason: str = "") -> SettingView:
    _tunable(key)
    await _apply(claims, key=key, new=DEFAULT_MARK, action="config.reset", reason=reason, extra={})
    return await _one(claims, key)


async def revert(claims: SessionClaims, change_id: int) -> SettingView:
    """Put a setting back to the value it had before change `change_id` (validated again)."""
    async with db_session(_ctx(claims)) as session:
        row = await session.get(AuditLog, change_id)
        if row is None or row.action not in CONFIG_ACTIONS:
            raise NotFoundError("change_not_found", "This change is not in the configuration history.")
        key, old = row.metadata_.get("key", ""), row.metadata_.get("old", "")
    t = _tunable(key)
    if old == DEFAULT_MARK:
        target: object = DEFAULT_MARK
    else:
        try:
            target = coerce(t, json.loads(old))
        except (ValueError, InvalidValueError) as exc:
            raise UnprocessableError(
                "setting_not_revertible", "That earlier value is no longer allowed."
            ) from exc
    await _apply(
        claims,
        key=key,
        new=target,
        action="config.reverted",
        reason="",
        extra={"reverted_change": str(change_id)},
    )
    return await _one(claims, key)


async def _one(claims: SessionClaims, key: str) -> SettingView:
    return next(s for s in (await view(claims)).settings if s.key == key)
