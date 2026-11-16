"""Notification settings and alert-log persistence (repository layer, RLS-scoped sessions).

Users read and write their own settings; only 'system' (the alert job) writes `notifications`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import Notification, NotificationSettings


@dataclass(frozen=True, slots=True)
class Prefs:
    """Effective settings; a user without a row gets the defaults (e-mail on, every change on)."""

    email_enabled: bool = True
    notify_new: bool = True
    notify_regression: bool = True
    notify_fixed: bool = True
    slack_webhook_enc: str | None = None


def prefs_of(row: NotificationSettings | None) -> Prefs:
    if row is None:
        return Prefs()
    return Prefs(
        email_enabled=row.email_enabled,
        notify_new=row.notify_new,
        notify_regression=row.notify_regression,
        notify_fixed=row.notify_fixed,
        slack_webhook_enc=row.slack_webhook_enc,
    )


async def get_settings(session: AsyncSession, user_id: uuid.UUID) -> NotificationSettings | None:
    stmt = select(NotificationSettings).where(NotificationSettings.user_id == user_id)
    return (await session.execute(stmt)).scalar_one_or_none()


async def upsert_settings(
    session: AsyncSession,
    user_id: uuid.UUID,
    *,
    flags: dict[str, bool],
    slack_webhook_enc: str | None,
    replace_slack: bool,
) -> None:
    """Insert or update the user's row. `replace_slack=False` keeps the stored webhook."""
    values: dict[str, object] = {**flags, "updated_at": func.now()}
    if replace_slack:
        values["slack_webhook_enc"] = slack_webhook_enc
    stmt = insert(NotificationSettings).values(user_id=user_id, **values)
    await session.execute(stmt.on_conflict_do_update(index_elements=["user_id"], set_=values))


async def history(session: AsyncSession, user_id: uuid.UUID, limit: int) -> list[Notification]:
    # Explicit user filter: RLS also lets privileged roles read other users' alert history.
    stmt = (
        select(Notification)
        .where(Notification.user_id == user_id)
        .order_by(Notification.created_at.desc(), Notification.id)
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())


async def ensure_notification(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    project_id: uuid.UUID,
    scan_id: uuid.UUID,
    channel: str,
    new_count: int,
    regression_count: int,
    fixed_count: int,
) -> None:
    """Create the (scan, channel) row once; a retry or a duplicate job finds the existing row."""
    stmt = insert(Notification).values(
        user_id=user_id,
        project_id=project_id,
        scan_id=scan_id,
        channel=channel,
        status="pending",
        new_count=new_count,
        regression_count=regression_count,
        fixed_count=fixed_count,
    )
    await session.execute(stmt.on_conflict_do_nothing(index_elements=["scan_id", "channel"]))


async def lock_notification(session: AsyncSession, scan_id: uuid.UUID, channel: str) -> Notification | None:
    """Lock the row for sending; None if another worker is sending it right now."""
    stmt = (
        select(Notification)
        .where(Notification.scan_id == scan_id, Notification.channel == channel)
        .with_for_update(skip_locked=True)
    )
    return (await session.execute(stmt)).scalar_one_or_none()
