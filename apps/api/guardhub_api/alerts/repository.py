"""Notification settings and alert-log persistence (repository layer, RLS-scoped sessions).

Users read and write their own settings; only 'system' (the alert jobs) writes `notifications`
and `notification_events`.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import Notification, NotificationEvent, NotificationSettings


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


HistoryFilter = Literal["alerts", "test", "all"]


async def history(
    session: AsyncSession, user_id: uuid.UUID, limit: int, show: HistoryFilter = "alerts"
) -> list[Notification | NotificationEvent]:
    """The newest `limit` alerts across both tables, newest first.

    "alerts" = real alerts (scan changes + monitoring paused); "test" = test messages only;
    "all" = everything. Explicit user filter: RLS also lets privileged roles read other users'
    rows. Taking the top `limit` of each table and merging them gives the exact overall top.
    """
    rows: list[Notification | NotificationEvent] = []
    if show != "test":
        stmt = (
            select(Notification)
            .where(Notification.user_id == user_id)
            .order_by(Notification.created_at.desc(), Notification.id)
            .limit(limit)
        )
        rows.extend((await session.execute(stmt)).scalars().all())
    kinds = {"alerts": ["monitoring_paused"], "test": ["test"], "all": ["monitoring_paused", "test"]}[show]
    stmt_events = (
        select(NotificationEvent)
        .where(NotificationEvent.user_id == user_id, NotificationEvent.kind.in_(kinds))
        .order_by(NotificationEvent.created_at.desc(), NotificationEvent.id)
        .limit(limit)
    )
    rows.extend((await session.execute(stmt_events)).scalars().all())
    rows.sort(key=lambda r: (r.created_at, str(r.id)), reverse=True)
    return rows[:limit]


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


async def ensure_event(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    project_id: uuid.UUID | None,
    kind: str,
    dedupe_key: str,
    channel: str,
) -> None:
    """Create the (event, channel) row once; a retry or a duplicate job finds the existing row."""
    stmt = insert(NotificationEvent).values(
        user_id=user_id,
        project_id=project_id,
        kind=kind,
        dedupe_key=dedupe_key,
        channel=channel,
        status="pending",
    )
    await session.execute(stmt.on_conflict_do_nothing(index_elements=["dedupe_key", "channel"]))


async def lock_event(session: AsyncSession, dedupe_key: str, channel: str) -> NotificationEvent | None:
    """Lock the row for sending; None if another worker is sending it right now."""
    stmt = (
        select(NotificationEvent)
        .where(NotificationEvent.dedupe_key == dedupe_key, NotificationEvent.channel == channel)
        .with_for_update(skip_locked=True)
    )
    return (await session.execute(stmt)).scalar_one_or_none()
