"""Project HTTP routes (docs/architecture.md §4.4). Every route needs an MFA-complete session."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from guardhub_api.auth.deps import FullSession
from guardhub_api.common.redis import get_redis
from guardhub_api.projects import service
from guardhub_api.projects.schemas import (
    ClaimScanRequest,
    CreateProjectRequest,
    ProjectView,
    UpdateProjectRequest,
)
from guardhub_api.scans.schemas import ScanSummary

router = APIRouter(prefix="/projects", tags=["projects"])


@router.get("")
async def list_projects(claims: FullSession) -> list[ProjectView]:
    return await service.list_projects(claims)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_project(body: CreateProjectRequest, claims: FullSession) -> ProjectView:
    return await service.create_project(claims, name=body.name, target_url=body.target_url)


@router.post("/claim", status_code=status.HTTP_201_CREATED)
async def claim_scan(body: ClaimScanRequest, claims: FullSession) -> ProjectView:
    return await service.claim_anonymous_scan(
        claims, scan_id=body.scan_id, access_token=body.access_token, name=body.name
    )


@router.get("/{project_id}")
async def get_project(project_id: uuid.UUID, claims: FullSession) -> ProjectView:
    return await service.get_project(claims, project_id)


@router.patch("/{project_id}")
async def rename_project(
    project_id: uuid.UUID, body: UpdateProjectRequest, claims: FullSession
) -> ProjectView:
    return await service.rename_project(claims, project_id, body.name)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(project_id: uuid.UUID, claims: FullSession) -> None:
    await service.delete_project(claims, project_id)


@router.post("/{project_id}/verify")
async def verify_project(project_id: uuid.UUID, claims: FullSession) -> ProjectView:
    return await service.verify_project(get_redis(), claims, project_id)


@router.get("/{project_id}/scans")
async def list_scans(project_id: uuid.UUID, claims: FullSession) -> list[ScanSummary]:
    return await service.list_scans(claims, project_id)


@router.post("/{project_id}/scans", status_code=status.HTTP_202_ACCEPTED)
async def rescan(project_id: uuid.UUID, claims: FullSession) -> ScanSummary:
    return await service.rescan(get_redis(), claims, project_id)
