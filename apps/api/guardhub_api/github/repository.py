"""GitHub installation persistence (repository layer)."""

from __future__ import annotations

import uuid

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import GitHubInstallation, Project


async def live_for_user(session: AsyncSession, user_id: uuid.UUID) -> list[GitHubInstallation]:
    stmt = (
        select(GitHubInstallation)
        .where(GitHubInstallation.user_id == user_id, GitHubInstallation.revoked_at.is_(None))
        .order_by(GitHubInstallation.created_at)
    )
    return list((await session.execute(stmt)).scalars().all())


async def get(session: AsyncSession, row_id: uuid.UUID) -> GitHubInstallation | None:
    stmt = select(GitHubInstallation).where(GitHubInstallation.id == row_id)
    return (await session.execute(stmt)).scalar_one_or_none()


async def live_by_installation(session: AsyncSession, installation_id: int) -> GitHubInstallation | None:
    stmt = select(GitHubInstallation).where(
        GitHubInstallation.installation_id == installation_id, GitHubInstallation.revoked_at.is_(None)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def add(session: AsyncSession, row: GitHubInstallation) -> GitHubInstallation:
    session.add(row)
    await session.flush()
    await session.refresh(row)
    return row


async def repo_projects(session: AsyncSession, row_id: uuid.UUID) -> list[Project]:
    stmt = select(Project).where(Project.github_installation_id == row_id, Project.kind == "repo")
    return list((await session.execute(stmt)).scalars().all())


async def detach_projects(session: AsyncSession, row_id: uuid.UUID) -> None:
    """Repo projects of a revoked installation keep their history but can no longer be scanned."""
    await session.execute(
        update(Project)
        .where(Project.github_installation_id == row_id)
        .values(ownership_verified_at=None, ownership_method=None, next_scan_at=None, scan_frequency="off")
    )
