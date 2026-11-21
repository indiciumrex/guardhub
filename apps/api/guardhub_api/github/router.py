"""GitHub connection routes (ADR-0006). Every route needs an MFA-complete session."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from guardhub_api.auth.deps import FullSession
from guardhub_api.common.redis import get_redis
from guardhub_api.github import client as github_client
from guardhub_api.github import service
from guardhub_api.github.client import GitHubClient
from guardhub_api.github.schemas import (
    AddRepoRequest,
    ConnectComplete,
    ConnectStart,
    GitHubStatus,
    InstallationView,
    RepoView,
)
from guardhub_api.projects import service as project_service
from guardhub_api.projects.schemas import ProjectView

router = APIRouter(prefix="/github", tags=["github"])


def client() -> GitHubClient:
    return github_client.make_client()


@router.get("")
async def github_status(claims: FullSession) -> GitHubStatus:
    return await service.status(claims)


@router.post("/connect")
async def connect_start(claims: FullSession) -> ConnectStart:
    return await service.start_connect(get_redis(), claims)


@router.post("/installations", status_code=status.HTTP_201_CREATED)
async def connect_complete(body: ConnectComplete, claims: FullSession) -> InstallationView:
    return await service.complete_connect(
        get_redis(),
        claims,
        code=body.code,
        installation_id=body.installation_id,
        state=body.state,
        client=client(),
    )


@router.get("/installations/{row_id}/repositories")
async def list_repositories(row_id: uuid.UUID, claims: FullSession) -> list[RepoView]:
    return await service.list_repositories(claims, row_id, client())


@router.post("/installations/{row_id}/repositories", status_code=status.HTTP_201_CREATED)
async def add_repository(row_id: uuid.UUID, body: AddRepoRequest, claims: FullSession) -> ProjectView:
    project_id = await service.add_repository(claims, row_id, body.repo_id, client())
    return await project_service.get_project(claims, project_id)


@router.delete("/installations/{row_id}", status_code=status.HTTP_204_NO_CONTENT)
async def disconnect(row_id: uuid.UUID, claims: FullSession) -> None:
    await service.disconnect(claims, row_id, client())
