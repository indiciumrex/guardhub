"""Persistence for `admin_trusted_domains` (repository layer).

RLS limits every query to the owning admin ('admin' context) or 'system'; the explicit
`admin_user_id` filters are a second, independent guard. Revoked rows are kept for history and
are invisible to every lookup here except the background re-check's status filter.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import AdminTrustedDomain

LIVE_STATUSES = ("pending", "active", "suspended")
RECHECK_STATUSES = ("active", "suspended")


async def list_live(session: AsyncSession, admin_user_id: uuid.UUID) -> list[AdminTrustedDomain]:
    stmt = (
        select(AdminTrustedDomain)
        .where(
            AdminTrustedDomain.admin_user_id == admin_user_id,
            AdminTrustedDomain.status.in_(LIVE_STATUSES),
        )
        .order_by(AdminTrustedDomain.created_at.desc())
    )
    return list((await session.execute(stmt)).scalars().all())


async def count_live(session: AsyncSession, admin_user_id: uuid.UUID) -> int:
    stmt = (
        select(func.count())
        .select_from(AdminTrustedDomain)
        .where(
            AdminTrustedDomain.admin_user_id == admin_user_id,
            AdminTrustedDomain.status.in_(LIVE_STATUSES),
        )
    )
    return int((await session.execute(stmt)).scalar_one())


async def get_live(
    session: AsyncSession, admin_user_id: uuid.UUID, domain_id: uuid.UUID, *, for_update: bool = False
) -> AdminTrustedDomain | None:
    stmt = select(AdminTrustedDomain).where(
        AdminTrustedDomain.id == domain_id,
        AdminTrustedDomain.admin_user_id == admin_user_id,
        AdminTrustedDomain.status.in_(LIVE_STATUSES),
    )
    if for_update:
        stmt = stmt.with_for_update()
    return (await session.execute(stmt)).scalar_one_or_none()


async def live_for_host(
    session: AsyncSession, admin_user_id: uuid.UUID, host: str
) -> AdminTrustedDomain | None:
    stmt = select(AdminTrustedDomain).where(
        AdminTrustedDomain.admin_user_id == admin_user_id,
        AdminTrustedDomain.host == host,
        AdminTrustedDomain.status.in_(LIVE_STATUSES),
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def active_for_origin(
    session: AsyncSession, admin_user_id: uuid.UUID, origin: str, proven_since: datetime
) -> AdminTrustedDomain | None:
    """The admin's ACTIVE domain whose verified origin equals `origin` exactly (scheme + host + port),
    proven no earlier than `proven_since`."""
    stmt = select(AdminTrustedDomain).where(
        AdminTrustedDomain.admin_user_id == admin_user_id,
        AdminTrustedDomain.target_origin == origin,
        AdminTrustedDomain.status == "active",
        AdminTrustedDomain.verified_at.is_not(None),
        AdminTrustedDomain.verified_at >= proven_since,
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def add(session: AsyncSession, domain: AdminTrustedDomain) -> AdminTrustedDomain:
    session.add(domain)
    await session.flush()
    await session.refresh(domain)
    return domain


async def ids_to_recheck(session: AsyncSession) -> list[uuid.UUID]:
    """Every active or suspended domain, oldest check first ('system' context only)."""
    stmt = (
        select(AdminTrustedDomain.id)
        .where(AdminTrustedDomain.status.in_(RECHECK_STATUSES))
        .order_by(AdminTrustedDomain.last_checked_at.asc().nulls_first())
    )
    return list((await session.execute(stmt)).scalars().all())


async def get_for_recheck(session: AsyncSession, domain_id: uuid.UUID) -> AdminTrustedDomain | None:
    stmt = (
        select(AdminTrustedDomain)
        .where(AdminTrustedDomain.id == domain_id, AdminTrustedDomain.status.in_(RECHECK_STATUSES))
        .with_for_update()
    )
    return (await session.execute(stmt)).scalar_one_or_none()
