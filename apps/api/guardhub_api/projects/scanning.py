"""Starting a scan of a saved project: the ONE path shared by manual rescans and scheduled scans.

Rules (§9.2, ADR-0001, ADR-0003, docs/architecture.md §8.2/§8.5):
- the project must be verified (422 `ownership_not_verified`);
- a proof older than `REVERIFY_AFTER` is re-checked through the scanner before scanning;
- a `trusted_domain` project needs its admin's trusted domain for that exact origin to be
  `active` (422 `trusted_domain_inactive`);
- one scan at a time per project (409 `scan_in_progress`);
- a `repo` project (ADR-0006) is proven by its GitHub App installation instead: every scan mints a
  token narrowed to that repository, so lost access shows up as 422 `repo_access_lost`.
It does not check WHO is asking: callers do (owner check for users, 'system' for the scheduler).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.admin.trusted_domains.ownership import TRUSTED_DOMAIN_METHOD, require_trusted_domain
from guardhub_api.common import audit
from guardhub_api.common.errors import (
    ConflictError,
    NotFoundError,
    ServiceUnavailableError,
    UnprocessableError,
)
from guardhub_api.config import get_settings
from guardhub_api.db.models import Project, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.github import client as github_client
from guardhub_api.github import repository as github_repo
from guardhub_api.github.client import GitHubAccessError, GitHubClient, GitHubUnavailableError
from guardhub_api.github.service import mark_revoked
from guardhub_api.projects import repository
from guardhub_api.projects.verification import prove_ownership
from guardhub_api.scans import repository as scan_repo
from guardhub_api.scans import service as scan_service
from guardhub_api.scans.schemas import ScanTrigger

REVERIFY_AFTER = timedelta(days=30)


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


async def record_proof(session: AsyncSession, project: Project, method: str, actor: str) -> None:
    project.ownership_verified_at = datetime.now(UTC)
    project.ownership_method = method
    await audit.record(
        session, actor=actor, action="project.verified", target=str(project.id), metadata={"method": method}
    )


async def ensure_fresh_ownership(redis: Redis, target: ScanTarget, *, ctx: DbContext, actor: str) -> None:
    """Raise unless the ownership proof is valid right now (re-proving a stale one)."""
    if target.method == TRUSTED_DOMAIN_METHOD:
        # The single trusted-domain rule (ADR-0003): admin role re-read from the DB, an ACTIVE
        # domain of that admin for exactly this origin, proven within 30 days; else 422.
        await require_trusted_domain(target.user_id, target.origin)
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


def repo_access_lost() -> UnprocessableError:
    return UnprocessableError(
        "repo_access_lost", "GuardHub can no longer read this repository. Reconnect GitHub or share it again."
    )


@dataclass(frozen=True, slots=True)
class _RepoRef:
    installation_row: uuid.UUID | None
    repo_id: int
    full_name: str


async def repo_token(ref: _RepoRef, *, actor: str, client: GitHubClient | None = None) -> str:
    """Mint the per-scan token (contents:read on this one repository). Lost access → 422."""
    if not get_settings().github_configured:
        raise ServiceUnavailableError("github_not_configured", "GitHub connection is not available yet.")
    if ref.installation_row is None:
        raise repo_access_lost()
    async with db_session(DbContext.system()) as session:
        row = await github_repo.get(session, ref.installation_row)
        if row is None or row.revoked_at is not None:
            raise repo_access_lost()
        installation_id = row.installation_id
    client = client or github_client.make_client()
    try:
        return await client.installation_token(installation_id, ref.repo_id)
    except GitHubAccessError as exc:
        try:
            await client.installation(installation_id)
        except GitHubAccessError:
            await mark_revoked(ref.installation_row, actor)  # uninstalled on GitHub's side
        except GitHubUnavailableError:
            pass
        raise repo_access_lost() from exc
    except GitHubUnavailableError as exc:
        raise ServiceUnavailableError(
            "github_unavailable", "GitHub did not answer. Please try again."
        ) from exc


async def start_project_scan(
    redis: Redis,
    *,
    project_id: uuid.UUID,
    ctx: DbContext,
    actor: str,
    trigger: ScanTrigger,
    github: GitHubClient | None = None,
) -> Scan:
    async with db_session(ctx) as session:
        project = await repository.get(session, project_id)
        if project is None:
            raise NotFoundError("project_not_found", "Project not found.")
        target = ScanTarget.of(project)
        ref = (
            _RepoRef(project.github_installation_id, project.repo_id, project.repo_full_name)
            if project.kind == "repo" and project.repo_id is not None and project.repo_full_name
            else None
        )
        if target.verified_at is None and target.method != TRUSTED_DOMAIN_METHOD:
            raise not_verified()
        if await scan_repo.has_active(session, project_id):
            raise ConflictError("scan_in_progress", "A scan is already running for this project.")
    if ref is not None:
        token = await repo_token(ref, actor=actor, client=github)
        scan = await scan_service.create_and_enqueue(
            redis,
            target=target.origin,
            project_id=project_id,
            user_id=target.user_id,
            verification_id=None,
            public_token_hash=None,
            ctx=ctx,
            trigger=trigger,
            repo=scan_service.RepoJob(full_name=ref.full_name, token=token),
        )
        async with db_session(ctx) as session:
            await audit.record(
                session,
                actor=actor,
                action="scan.create",
                target=str(scan.id),
                metadata={"trigger": trigger, "kind": "repo"},
            )
        return scan
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
