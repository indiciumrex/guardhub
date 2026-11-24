"""Append-only audit log writer (§6, §9.1). Each sensitive action records one row.

The table rejects UPDATE/DELETE at the database level, so a row can't be altered once written.
Metadata must never contain secrets (passwords, tokens, codes).
"""

from __future__ import annotations

from contextvars import ContextVar

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import AuditLog

# The keyed hash of the requesting client's IP (set per HTTP request by the API middleware; never
# the IP itself). Rows written outside a request (worker, scheduler) carry none.
request_ip_hash: ContextVar[str | None] = ContextVar("audit_request_ip_hash", default=None)


async def record(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    target: str = "",
    metadata: dict[str, str] | None = None,
) -> None:
    meta = dict(metadata or {})
    ip_hash = request_ip_hash.get()
    if ip_hash and "ip_hash" not in meta:
        meta["ip_hash"] = ip_hash
    # Core INSERT without RETURNING: regular users may append audit rows but (by RLS) never read them.
    await session.execute(insert(AuditLog).values(actor=actor, action=action, target=target, metadata_=meta))


async def list_recent(
    session: AsyncSession,
    limit: int,
    offset: int = 0,
    *,
    action: str | None = None,
    actor: str | None = None,
    target: str | None = None,
) -> list[AuditLog]:
    """Newest first, optionally filtered (action prefix, exact actor or target). RLS limits reads
    to admin/system contexts."""
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action, autoescape=True))
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if target:
        stmt = stmt.where(AuditLog.target == target)
    stmt = stmt.order_by(AuditLog.id.desc()).limit(limit).offset(offset)
    return list((await session.execute(stmt)).scalars().all())
