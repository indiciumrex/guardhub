"""Append-only audit log writer (§6, §9.1). Each sensitive action records one row.

The table rejects UPDATE/DELETE at the database level, so a row can't be altered once written.
Metadata must never contain secrets (passwords, tokens, codes).
"""

from __future__ import annotations

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import AuditLog


async def record(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    target: str = "",
    metadata: dict[str, str] | None = None,
) -> None:
    # Core INSERT without RETURNING: regular users may append audit rows but (by RLS) never read them.
    await session.execute(
        insert(AuditLog).values(actor=actor, action=action, target=target, metadata_=metadata or {})
    )


async def list_recent(session: AsyncSession, limit: int) -> list[AuditLog]:
    """Newest first. RLS limits reads to admin/system contexts."""
    return list(
        (await session.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit))).scalars().all()
    )
