"""Project and verification-challenge persistence (repository layer)."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import Project, TargetVerification


async def list_for_user(session: AsyncSession, user_id: uuid.UUID) -> list[Project]:
    stmt = select(Project).where(Project.user_id == user_id).order_by(Project.created_at.desc())
    return list((await session.execute(stmt)).scalars().all())


async def get(session: AsyncSession, project_id: uuid.UUID, *, for_update: bool = False) -> Project | None:
    stmt = select(Project).where(Project.id == project_id)
    if for_update:
        stmt = stmt.with_for_update()
    return (await session.execute(stmt)).scalar_one_or_none()


async def lock_due(session: AsyncSession, now: datetime, limit: int) -> list[Project]:
    """Scheduled, unpaused projects whose next run is due, oldest first. Rows another scheduler
    tick holds are skipped (FOR UPDATE SKIP LOCKED), so two ticks never claim the same project."""
    stmt = (
        select(Project)
        .where(
            Project.scan_frequency != "off",
            Project.schedule_paused_reason.is_(None),
            Project.next_scan_at.is_not(None),
            Project.next_scan_at <= now,
        )
        .order_by(Project.next_scan_at)
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    return list((await session.execute(stmt)).scalars().all())


async def by_target(session: AsyncSession, user_id: uuid.UUID, target_url: str) -> Project | None:
    stmt = select(Project).where(Project.user_id == user_id, Project.target_url == target_url)
    return (await session.execute(stmt)).scalar_one_or_none()


async def count_for_user(session: AsyncSession, user_id: uuid.UUID) -> int:
    stmt = select(func.count()).select_from(Project).where(Project.user_id == user_id)
    return int((await session.execute(stmt)).scalar_one())


async def add(session: AsyncSession, project: Project) -> Project:
    session.add(project)
    await session.flush()
    await session.refresh(project)
    return project


async def delete(session: AsyncSession, project: Project) -> None:
    await session.delete(project)
    await session.flush()


async def add_challenge(session: AsyncSession, challenge: TargetVerification) -> TargetVerification:
    session.add(challenge)
    await session.flush()
    await session.refresh(challenge)
    return challenge


async def get_challenge(session: AsyncSession, challenge_id: uuid.UUID) -> TargetVerification | None:
    stmt = select(TargetVerification).where(TargetVerification.id == challenge_id)
    return (await session.execute(stmt)).scalar_one_or_none()
