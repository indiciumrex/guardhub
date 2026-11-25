"""The append-only active_request_log (ADR-0008 §7): what an active scan sent, request by request.

Retention is 30 days (founder decision 2026-11-25): `purge_expired` runs daily from the jobs
worker and calls `active_request_log_purge()` (migration 0018), the only way a row can leave the
table; the database refuses any other DELETE and every UPDATE.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import exists, insert, select, text
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


RETENTION_DAYS = 30  # fixed in migration 0018; shown here for logs and the audit record
PURGE_ACTOR = "system:active-log-retention"


async def purge_expired(session: AsyncSession) -> int:
    """Delete entries recorded more than RETENTION_DAYS ago. Returns how many were removed."""
    return int(await session.scalar(text("SELECT active_request_log_purge()")) or 0)
