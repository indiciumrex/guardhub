"""GitHub connection logic (ADR-0006 §3-§5).

Connect: a single-use `state` (Redis, 10 minutes, bound to the user who started) → GitHub's install
screen → callback with `code` + `installation_id` + `state`. The installation is bound to the
user only after GitHub confirms, through the code exchange, that this GitHub user can access that
installation; the user token is revoked right away. Repositories become projects of kind "repo",
verified by the installation. Disconnect uninstalls the App at GitHub and keeps the history.
Every connection change is audited. Nothing here stores a GitHub token.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime
from urllib.parse import quote

from redis.asyncio import Redis
from sqlalchemy.exc import IntegrityError

from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit, ratelimit
from guardhub_api.common.errors import (
    ConflictError,
    NotFoundError,
    ServiceUnavailableError,
    UnprocessableError,
)
from guardhub_api.config import get_settings
from guardhub_api.db.models import GitHubInstallation, Project
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.github import repository
from guardhub_api.github.client import GitHubAccessError, GitHubClient, GitHubUnavailableError
from guardhub_api.github.schemas import ConnectStart, GitHubStatus, InstallationView, RepoView
from guardhub_api.projects import repository as project_repo
from guardhub_api.projects.verification import new_token

STATE_TTL_SECONDS = 600
OWNERSHIP_METHOD = "github_app"
MAX_PROJECTS_PER_USER = 25  # same limit as site projects (projects.service)


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext.for_user(claims.user_id, claims.role)


def _actor(claims: SessionClaims) -> str:
    return f"user:{claims.user_id}"


def _state_key(state: str) -> str:
    return "gh:github-connect:" + hashlib.sha256(state.encode()).hexdigest()


def _require_configured() -> None:
    if not get_settings().github_configured:
        raise ServiceUnavailableError("github_not_configured", "GitHub connection is not available yet.")


def _unavailable(exc: Exception) -> ServiceUnavailableError:
    return ServiceUnavailableError("github_unavailable", "GitHub did not answer. Please try again.")


def repo_url(full_name: str) -> str:
    return f"https://github.com/{full_name}"


async def status(claims: SessionClaims) -> GitHubStatus:
    async with db_session(_ctx(claims)) as session:
        rows = await repository.live_for_user(session, claims.user_id)
        return GitHubStatus(
            configured=get_settings().github_configured,
            installations=[
                InstallationView(
                    id=r.id,
                    account_login=r.account_login,
                    account_type=r.account_type,
                    created_at=r.created_at,
                )
                for r in rows
            ],
        )


async def start_connect(redis: Redis, claims: SessionClaims) -> ConnectStart:
    _require_configured()
    await ratelimit.enforce(redis, "github-connect", str(claims.user_id), limit=10, window=600)
    state = secrets.token_urlsafe(32)
    await redis.set(_state_key(state), str(claims.user_id), ex=STATE_TTL_SECONDS)
    settings = get_settings()
    url = f"{settings.github_web_url}/apps/{quote(settings.github_app_slug)}/installations/new?state={state}"
    return ConnectStart(install_url=url)


async def complete_connect(
    redis: Redis, claims: SessionClaims, *, code: str, installation_id: int, state: str, client: GitHubClient
) -> InstallationView:
    _require_configured()
    owner = await redis.getdel(_state_key(state))  # single use, whatever happens next
    if owner is None or str(owner) != str(claims.user_id):
        raise UnprocessableError("github_state_invalid", "This GitHub link expired. Please connect again.")
    try:
        user_token = await client.exchange_code(code)
        try:
            visible = await client.user_installation_ids(user_token)
        finally:
            await client.revoke_user_token(user_token)
        if installation_id not in visible:
            # The callback named an installation this GitHub user cannot access: never bind it.
            raise UnprocessableError(
                "github_installation_not_yours", "That GitHub installation is not yours."
            )
        info = await client.installation(installation_id)
    except GitHubAccessError as exc:
        raise UnprocessableError(
            "github_state_invalid", "This GitHub link expired. Please connect again."
        ) from exc
    except GitHubUnavailableError as exc:
        raise _unavailable(exc) from exc
    if info.account_type not in ("User", "Organization") or not info.account_login:
        raise ServiceUnavailableError("github_unavailable", "GitHub returned an unexpected installation.")
    async with db_session(_ctx(claims)) as session:
        for existing in await repository.live_for_user(session, claims.user_id):
            if existing.installation_id == installation_id:
                return InstallationView(
                    id=existing.id,
                    account_login=existing.account_login,
                    account_type=existing.account_type,
                    created_at=existing.created_at,
                )
    try:
        async with db_session(_ctx(claims)) as session:
            row = await repository.add(
                session,
                GitHubInstallation(
                    user_id=claims.user_id,
                    installation_id=installation_id,
                    account_login=info.account_login[:100],
                    account_type=info.account_type,
                ),
            )
            await audit.record(
                session,
                actor=_actor(claims),
                action="github.connect",
                target=str(row.id),
                metadata={"installation": str(installation_id), "account": row.account_login},
            )
            return InstallationView(
                id=row.id,
                account_login=row.account_login,
                account_type=row.account_type,
                created_at=row.created_at,
            )
    except IntegrityError as exc:  # live on another GuardHub account (one owner per installation)
        raise ConflictError(
            "github_installation_taken", "This GitHub installation is connected to another account."
        ) from exc


async def _owned_live(claims: SessionClaims, row_id: uuid.UUID) -> GitHubInstallation:
    async with db_session(_ctx(claims)) as session:
        row = await repository.get(session, row_id)
        if row is None or row.user_id != claims.user_id or row.revoked_at is not None:
            raise NotFoundError("github_installation_not_found", "GitHub connection not found.")
        return row


async def list_repositories(claims: SessionClaims, row_id: uuid.UUID, client: GitHubClient) -> list[RepoView]:
    _require_configured()
    row = await _owned_live(claims, row_id)
    try:
        repos = await client.repositories(row.installation_id)
    except GitHubAccessError as exc:
        raise UnprocessableError(
            "repo_access_lost", "GuardHub can no longer read this GitHub account."
        ) from exc
    except GitHubUnavailableError as exc:
        raise _unavailable(exc) from exc
    async with db_session(_ctx(claims)) as session:
        projects = {
            p.repo_id: p.id for p in await project_repo.list_for_user(session, claims.user_id) if p.repo_id
        }
    return [
        RepoView(
            repo_id=r.repo_id, full_name=r.full_name, private=r.private, project_id=projects.get(r.repo_id)
        )
        for r in sorted(repos, key=lambda r: r.full_name.lower())
    ]


async def add_repository(
    claims: SessionClaims, row_id: uuid.UUID, repo_id: int, client: GitHubClient
) -> uuid.UUID:
    """Make one selected repository a GuardHub project (verified by the installation)."""
    _require_configured()
    row = await _owned_live(claims, row_id)
    try:
        repos = {r.repo_id: r for r in await client.repositories(row.installation_id)}
    except GitHubAccessError as exc:
        raise UnprocessableError(
            "repo_access_lost", "GuardHub can no longer read this GitHub account."
        ) from exc
    except GitHubUnavailableError as exc:
        raise _unavailable(exc) from exc
    repo = repos.get(repo_id)
    if repo is None:  # not among the repositories the user granted: never added
        raise NotFoundError("repo_not_found", "That repository is not shared with GuardHub.")
    async with db_session(_ctx(claims)) as session:
        mine = await project_repo.list_for_user(session, claims.user_id)
        if any(p.repo_id == repo_id for p in mine):
            raise ConflictError("project_exists", "You already have a project for this repository.")
        if len(mine) >= MAX_PROJECTS_PER_USER:
            raise UnprocessableError("project_limit_reached", "Project limit reached.")
        project = await project_repo.add(
            session,
            Project(
                user_id=claims.user_id,
                name=repo.full_name[:120],
                target_url=repo_url(repo.full_name),
                verification_token=new_token(),
                ownership_verified_at=datetime.now(UTC),
                ownership_method=OWNERSHIP_METHOD,
                kind="repo",
                github_installation_id=row.id,
                repo_id=repo.repo_id,
                repo_full_name=repo.full_name,
            ),
        )
        await audit.record(
            session,
            actor=_actor(claims),
            action="project.create",
            target=str(project.id),
            metadata={"ownership_method": OWNERSHIP_METHOD, "repo": str(repo.repo_id)},
        )
        return project.id


async def disconnect(claims: SessionClaims, row_id: uuid.UUID, client: GitHubClient) -> None:
    """Uninstall at GitHub (every token dies), mark revoked, stop the repo projects."""
    _require_configured()
    row = await _owned_live(claims, row_id)
    try:
        await client.uninstall(row.installation_id)
    except GitHubUnavailableError as exc:
        raise _unavailable(exc) from exc
    async with db_session(_ctx(claims)) as session:
        live = await repository.get(session, row_id)
        if live is None or live.revoked_at is not None:
            return
        live.revoked_at = datetime.now(UTC)
        await repository.detach_projects(session, row_id)
        await audit.record(
            session,
            actor=_actor(claims),
            action="github.disconnect",
            target=str(row_id),
            metadata={"installation": str(row.installation_id)},
        )


async def mark_revoked(row_id: uuid.UUID, actor: str) -> None:
    """GitHub says the installation is gone (uninstalled there): record it once, stop its projects."""
    async with db_session(DbContext.system()) as session:
        row = await repository.get(session, row_id)
        if row is None or row.revoked_at is not None:
            return
        row.revoked_at = datetime.now(UTC)
        await repository.detach_projects(session, row_id)
        await audit.record(
            session,
            actor=actor,
            action="github.revoked_upstream",
            target=str(row_id),
            metadata={"installation": str(row.installation_id)},
        )
