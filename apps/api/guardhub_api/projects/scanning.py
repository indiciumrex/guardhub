"""Starting a scan of a saved project: the ONE path shared by manual rescans and scheduled scans.

Rules (§9.2, ADR-0001, ADR-0003, docs/architecture.md §8.2/§8.5):
- the project must be verified (422 `ownership_not_verified`);
- a proof older than `REVERIFY_AFTER` is re-checked through the scanner before scanning;
- a `trusted_domain` project needs its admin's trusted domain for that exact origin to be
  `active` (422 `trusted_domain_inactive`);
- one scan at a time per project (409 `scan_in_progress`).
It does not check WHO is asking: callers do (owner check for users, 'system' for the scheduler).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.common import audit
from guardhub_api.common.errors import ConflictError, NotFoundError, UnprocessableError
from guardhub_api.db.models import AdminTrustedDomain, Project, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.projects import repository
from guardhub_api.projects.verification import prove_ownership
from guardhub_api.scans import repository as scan_repo
from guardhub_api.scans import service as scan_service
from guardhub_api.scans.schemas import ScanTrigger

REVERIFY_AFTER = timedelta(days=30)
TRUSTED_DOMAIN_METHOD = "trusted_domain"


@dataclass(frozen=True, slots=True)
class ScanTarget:
    project_id: uuid.UUID
    user_id: uuid.UUID
    origin: str
    token: str
    verified_at: datetime | None
    method: str | None

    @staticmethod
    def of(project: Project) -> ScanTarget:
        return ScanTarget(
            project_id=project.id,
            user_id=project.user_id,
            origin=project.target_url,
            token=project.verification_token,
            verified_at=project.ownership_verified_at,
            method=project.ownership_method,
        )


def not_verified() -> UnprocessableError:
    return UnprocessableError("ownership_not_verified", "Verify that you own this site first.")


async def trusted_domain_active(session: AsyncSession, *, admin_user_id: uuid.UUID, origin: str) -> bool:
    """Exact origin (scheme + host + port) of an `active` trusted domain of that admin (ADR-0003)."""
    stmt = (
        select(func.count())
        .select_from(AdminTrustedDomain)
        .where(
            AdminTrustedDomain.admin_user_id == admin_user_id,
            AdminTrustedDomain.target_origin == origin,
            AdminTrustedDomain.status == "active",
        )
    )
    return int((await session.execute(stmt)).scalar_one()) > 0


async def record_proof(session: AsyncSession, project: Project, method: str, actor: str) -> None:
    project.ownership_verified_at = datetime.now(UTC)
    project.ownership_method = method
    await audit.record(
        session, actor=actor, action="project.verified", target=str(project.id), metadata={"method": method}
    )


async def ensure_fresh_ownership(redis: Redis, target: ScanTarget, *, ctx: DbContext, actor: str) -> None:
    """Raise unless the ownership proof is valid right now (re-proving a stale one)."""
    if target.method == TRUSTED_DOMAIN_METHOD:
        async with db_session(ctx) as session:
            if not await trusted_domain_active(session, admin_user_id=target.user_id, origin=target.origin):
                raise UnprocessableError(
                    "trusted_domain_inactive", "The trusted domain for this site is not active."
                )
        return
    if target.verified_at is None:
        raise not_verified()
    if datetime.now(UTC) - target.verified_at <= REVERIFY_AFTER:
        return
    method = await prove_ownership(redis, origin=target.origin, token=target.token)
    async with db_session(ctx) as session:
        project = await repository.get(session, target.project_id)
        if project is None:
            raise NotFoundError("project_not_found", "Project not found.")
        await record_proof(session, project, method, actor)


async def start_project_scan(
    redis: Redis, *, project_id: uuid.UUID, ctx: DbContext, actor: str, trigger: ScanTrigger
) -> Scan:
    async with db_session(ctx) as session:
        project = await repository.get(session, project_id)
        if project is None:
            raise NotFoundError("project_not_found", "Project not found.")
        target = ScanTarget.of(project)
        if target.verified_at is None and target.method != TRUSTED_DOMAIN_METHOD:
            raise not_verified()
        if await scan_repo.has_active(session, project_id):
            raise ConflictError("scan_in_progress", "A scan is already running for this project.")
    await ensure_fresh_ownership(redis, target, ctx=ctx, actor=actor)
    scan = await scan_service.create_and_enqueue(
        redis,
        target=target.origin,
        project_id=project_id,
        user_id=target.user_id,
        verification_id=None,
        public_token_hash=None,
        ctx=ctx,
        trigger=trigger,
    )
    async with db_session(ctx) as session:
        await audit.record(
            session, actor=actor, action="scan.create", target=str(scan.id), metadata={"trigger": trigger}
        )
    return scan
