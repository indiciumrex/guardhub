"""Project business logic: CRUD, ownership verification, re-scan, and claiming anonymous scans.

Rules: a project can only be scanned once ownership has been verified (§9.2). Verification
older than 30 days is re-checked automatically before the next scan (`projects.scanning`, shared
with the scheduler). All operations run in the caller's RLS context AND check that the caller owns
the project (RLS alone would let the admin role act on other users' projects). Only the claim's
ownership transfer uses 'system', and only after the scan access token has been validated.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.admin.trusted_domains.ownership import (
    TRUSTED_DOMAIN_METHOD,
    trusted_domain_covers,
)
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit, ratelimit
from guardhub_api.common.crypto import keyed_hash
from guardhub_api.common.errors import ConflictError, NotFoundError, UnprocessableError
from guardhub_api.common.urls import normalize_origin
from guardhub_api.config import get_settings
from guardhub_api.db.models import Project, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.platform import service as platform
from guardhub_api.projects import repository, schedule
from guardhub_api.projects.scanning import record_proof, start_project_scan
from guardhub_api.projects.schemas import ProjectView
from guardhub_api.projects.verification import instructions, new_token, prove_ownership
from guardhub_api.scans import repository as scan_repo
from guardhub_api.scans import service as scan_service
from guardhub_api.scans.schemas import ScanSummary, TrendPoint

MAX_PROJECTS_PER_USER = 25


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext.for_user(claims.user_id, claims.role)


def _actor(claims: SessionClaims) -> str:
    return f"user:{claims.user_id}"


def _view(project: Project, last_scan: ScanSummary | None) -> ProjectView:
    return ProjectView(
        id=project.id,
        name=project.name,
        kind="repo" if project.kind == "repo" else "site",
        repo_full_name=project.repo_full_name,
        target_url=project.target_url,
        verified=project.ownership_verified_at is not None,
        ownership_verified_at=project.ownership_verified_at,
        verification=instructions(project.target_url, project.verification_token),
        last_scan=last_scan,
        scan_frequency=project.scan_frequency,
        next_scan_at=project.next_scan_at,
        schedule_paused_reason=project.schedule_paused_reason,
        created_at=project.created_at,
    )


async def list_projects(claims: SessionClaims) -> list[ProjectView]:
    async with db_session(_ctx(claims)) as session:
        projects = await repository.list_for_user(session, claims.user_id)
        latest = await scan_repo.latest_for_projects(session, [p.id for p in projects])
        summaries = {s.id: s for s in await scan_service.summaries(session, list(latest.values()))}
        return [_view(p, summaries.get(latest[p.id].id) if p.id in latest else None) for p in projects]


async def _get_owned(session: AsyncSession, project_id: uuid.UUID, user_id: uuid.UUID) -> Project:
    project = await repository.get(session, project_id)
    # RLS hides other users' projects from users, but the admin role can READ them: check the owner
    # too. "Not yours" looks the same as "missing".
    if project is None or project.user_id != user_id:
        raise NotFoundError("project_not_found", "Project not found.")
    return project


async def get_project(claims: SessionClaims, project_id: uuid.UUID) -> ProjectView:
    async with db_session(_ctx(claims)) as session:
        project = await _get_owned(session, project_id, claims.user_id)
        latest = await scan_repo.latest_for_projects(session, [project.id])
        last = (
            (await scan_service.summaries(session, [latest[project.id]]))[0] if project.id in latest else None
        )
        return _view(project, last)


async def create_project(claims: SessionClaims, *, name: str, target_url: str) -> ProjectView:
    origin = normalize_origin(target_url, allow_private_hosts=get_settings().private_host_allowlist)
    # ADR-0003: an admin's ACTIVE trusted domain for exactly this origin counts as the proof.
    trusted = await trusted_domain_covers(claims.user_id, origin)
    async with db_session(_ctx(claims)) as session:
        if await repository.count_for_user(session, claims.user_id) >= MAX_PROJECTS_PER_USER:
            raise UnprocessableError("project_limit_reached", "Project limit reached.")
        if await repository.by_target(session, claims.user_id, origin) is not None:
            raise ConflictError("project_exists", "You already have a project for this address.")
        project = await repository.add(
            session,
            Project(
                user_id=claims.user_id,
                name=name.strip(),
                target_url=origin,
                verification_token=new_token(),
                ownership_verified_at=datetime.now(UTC) if trusted else None,
                ownership_method=TRUSTED_DOMAIN_METHOD if trusted else None,
            ),
        )
        await audit.record(
            session,
            actor=_actor(claims),
            action="project.create",
            target=str(project.id),
            metadata={"ownership_method": TRUSTED_DOMAIN_METHOD} if trusted else None,
        )
        return _view(project, None)


async def update_project(
    claims: SessionClaims, project_id: uuid.UUID, *, name: str | None, scan_frequency: str | None
) -> ProjectView:
    """Rename and/or set the monitoring schedule (§8.2)."""
    async with db_session(_ctx(claims)) as session:
        project = await _get_owned(session, project_id, claims.user_id)
        if name is not None:
            project.name = name.strip()
        if scan_frequency is not None:
            if scan_frequency != "off" and project.ownership_verified_at is None:
                raise UnprocessableError("ownership_not_verified", "Verify that you own this site first.")
            project.scan_frequency = scan_frequency
            project.next_scan_at = (
                None
                if scan_frequency == "off"
                else schedule.first_run(project.id, scan_frequency, datetime.now(UTC))
            )
            project.schedule_paused_reason = None  # setting it again resumes a paused schedule
            await audit.record(
                session,
                actor=_actor(claims),
                action="project.schedule_set",
                target=str(project_id),
                metadata={"frequency": scan_frequency},
            )
    return await get_project(claims, project_id)


async def delete_project(claims: SessionClaims, project_id: uuid.UUID) -> None:
    async with db_session(_ctx(claims)) as session:
        project = await _get_owned(session, project_id, claims.user_id)
        await repository.delete(session, project)
        await audit.record(session, actor=_actor(claims), action="project.delete", target=str(project_id))


async def verify_project(redis: Redis, claims: SessionClaims, project_id: uuid.UUID) -> ProjectView:
    await ratelimit.enforce(redis, "verify-project", str(project_id), limit=10, window=600)
    async with db_session(_ctx(claims)) as session:
        project = await _get_owned(session, project_id, claims.user_id)
        origin, token = project.target_url, project.verification_token
    method = await prove_ownership(redis, origin=origin, token=token)
    async with db_session(_ctx(claims)) as session:
        project = await _get_owned(session, project_id, claims.user_id)
        await record_proof(session, project, method, _actor(claims))
    return await get_project(claims, project_id)


async def rescan(redis: Redis, claims: SessionClaims, project_id: uuid.UUID) -> ScanSummary:
    limit = await platform.int_value("rate.rescan_per_project_hour")
    await ratelimit.enforce(redis, "rescan", str(project_id), limit=limit, window=3600)
    async with db_session(_ctx(claims)) as session:
        await _get_owned(session, project_id, claims.user_id)
    scan = await start_project_scan(
        redis, project_id=project_id, ctx=_ctx(claims), actor=_actor(claims), trigger="manual"
    )
    async with db_session(_ctx(claims)) as session:
        return (await scan_service.summaries(session, [scan]))[0]


async def list_scans(claims: SessionClaims, project_id: uuid.UUID) -> list[ScanSummary]:
    async with db_session(_ctx(claims)) as session:
        await _get_owned(session, project_id, claims.user_id)
        return await scan_service.summaries(session, await scan_repo.list_for_project(session, project_id))


async def trend(claims: SessionClaims, project_id: uuid.UUID, limit: int) -> list[TrendPoint]:
    """Done scans, oldest first (§8.3)."""
    async with db_session(_ctx(claims)) as session:
        await _get_owned(session, project_id, claims.user_id)
        scans = await scan_repo.done_trend(session, project_id, limit)
        return [
            TrendPoint(scan_id=s.id, finished_at=s.finished_at, score=s.score, trigger=s.trigger)
            for s in scans
        ]


async def claim_anonymous_scan(
    claims: SessionClaims, *, scan_id: uuid.UUID, access_token: str, name: str
) -> ProjectView:
    """Attach a verified anonymous scan to the user's account (the ADR-0001 'save this scan' flow)."""
    token_hash = keyed_hash(get_settings().hash_pepper.get_secret_value(), access_token)
    async with db_session(DbContext.anon(token_hash)) as session:
        scan = await scan_repo.get(session, scan_id)  # RLS: visible only with the right token
        if scan is None or scan.project_id is not None:
            raise NotFoundError("scan_not_found", "Scan not found or already saved.")
        origin, verification_id = scan.target_url, scan.verification_id

    async with db_session(_ctx(claims)) as session:
        project = await repository.by_target(session, claims.user_id, origin)
        if project is None:
            if await repository.count_for_user(session, claims.user_id) >= MAX_PROJECTS_PER_USER:
                raise UnprocessableError("project_limit_reached", "Project limit reached.")
            project = await repository.add(
                session,
                Project(
                    user_id=claims.user_id,
                    name=name.strip(),
                    target_url=origin,
                    verification_token=new_token(),
                ),
            )
        project_id = project.id

    # Ownership transfer of the anonymous rows: 'system' context, after the token was validated above.
    async with db_session(DbContext.system()) as session:
        scan_row: Scan | None = await scan_repo.get(session, scan_id, for_update=True)
        if scan_row is None or scan_row.project_id is not None or scan_row.public_token_hash != token_hash:
            raise NotFoundError("scan_not_found", "Scan not found or already saved.")
        scan_row.project_id = project_id
        scan_row.user_id = claims.user_id
        scan_row.public_token_hash = None
        challenge = await repository.get_challenge(session, verification_id) if verification_id else None
        owned = await repository.get(session, project_id)
        verified_challenge = challenge is not None and challenge.verified_at is not None
        if verified_challenge and owned is not None and owned.ownership_verified_at is None:
            assert challenge is not None
            owned.ownership_verified_at = challenge.verified_at
            owned.ownership_method = challenge.method
        await audit.record(
            session,
            actor=_actor(claims),
            action="scan.claim",
            target=str(scan_id),
            metadata={"project": str(project_id)},
        )
    return await get_project(claims, project_id)
