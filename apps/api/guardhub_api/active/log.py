"""The append-only active_request_log (ADR-0008 §6): what an active scan sent, request by request."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import exists, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import ActiveRequestLog


async def has_entries(session: AsyncSession, scan_id: uuid.UUID) -> bool:
    return bool(await session.scalar(select(exists().where(ActiveRequestLog.scan_id == scan_id))))


async def append(session: AsyncSession, rows: list[dict[str, Any]]) -> None:
    if rows:
        await session.execute(insert(ActiveRequestLog), rows)


async def for_scan(session: AsyncSession, scan_id: uuid.UUID, limit: int = 2000) -> list[ActiveRequestLog]:
    """Entries of one scan in order. RLS: the scan's owner and admins."""
    stmt = (
        select(ActiveRequestLog)
        .where(ActiveRequestLog.scan_id == scan_id)
        .order_by(ActiveRequestLog.id)
        .limit(limit)
    )
    return list((await session.execute(stmt)).scalars().all())
