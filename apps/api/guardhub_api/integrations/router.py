"""Integration routes.

- /integrations/*: authenticated by an API key only (never a session), acting as the key's
  owner in the user role. A triggered scan re-checks ownership proof (start_project_scan).
- /admin/integrations/*: the admin's screen (cookie session, admin only): keys and traffic.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Query
from pydantic import BaseModel
from sqlalchemy import func, select

from guardhub_api.auth.deps import AdminSession
from guardhub_api.common import ratelimit
from guardhub_api.common.errors import NotFoundError, UnprocessableError
from guardhub_api.common.redis import get_redis
from guardhub_api.db.models import Finding, Scan
from guardhub_api.db.session import db_session
from guardhub_api.integrations import keys, traffic
from guardhub_api.platform import service as platform
from guardhub_api.projects import repository as project_repo
from guardhub_api.projects.scanning import start_project_scan

router = APIRouter(prefix="/integrations", tags=["integrations"])
admin_router = APIRouter(prefix="/admin/integrations", tags=["admin"])


class IntegrationProject(BaseModel):
    id: uuid.UUID
    name: str
    kind: str
    target_url: str
    ownership_verified: bool


class IntegrationScan(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID | None
    status: str
    score: int | None
    created_at: datetime
    finished_at: datetime | None
    findings: dict[str, int]


class TriggeredScan(BaseModel):
    scan_id: uuid.UUID
    status: str


@router.get("/projects")
async def projects(principal: keys.ApiKeyPrincipal) -> list[IntegrationProject]:
    principal.require("projects:read")
    async with db_session(principal.ctx) as session:
        rows = await project_repo.list_for_user(session, principal.owner_id)
        return [
            IntegrationProject(
                id=p.id,
                name=p.name,
                kind=p.kind,
                target_url=p.target_url,
                ownership_verified=p.ownership_verified_at is not None,
            )
            for p in rows
        ]


@router.get("/scans/{scan_id}")
async def scan(scan_id: uuid.UUID, principal: keys.ApiKeyPrincipal) -> IntegrationScan:
    principal.require("scans:read")
    async with db_session(principal.ctx) as session:  # RLS: only the owner's scans exist here
        row = await session.get(Scan, scan_id)
        if row is None or row.user_id != principal.owner_id:
            raise NotFoundError("scan_not_found", "Scan not found.")
        counts = dict(
            (
                await session.execute(
                    select(Finding.severity, func.count())
                    .where(Finding.scan_id == scan_id)
                    .group_by(Finding.severity)
                )
            ).all()
        )
        return IntegrationScan(
            id=row.id,
            project_id=row.project_id,
            status=row.status,
            score=row.score,
            created_at=row.created_at,
            finished_at=row.finished_at,
            findings={k: int(v) for k, v in counts.items()},
        )


@router.post("/projects/{project_id}/scans", status_code=202)
async def trigger_scan(project_id: uuid.UUID, principal: keys.ApiKeyPrincipal) -> TriggeredScan:
    principal.require("scans:trigger")
    redis = get_redis()
    limit = await platform.int_value("rate.rescan_per_project_hour")
    await ratelimit.enforce(redis, "rescan", str(project_id), limit=limit, window=3600)
    started = await start_project_scan(
        redis, project_id=project_id, ctx=principal.ctx, actor=principal.actor, trigger="manual"
    )
    return TriggeredScan(scan_id=started.id, status=started.status)


# ---- admin ----


@admin_router.get("/keys")
async def list_keys(claims: AdminSession) -> list[keys.KeyView]:
    return await keys.list_keys(claims)


@admin_router.post("/keys", status_code=201)
async def create_key(body: keys.CreateKeyRequest, claims: AdminSession) -> keys.CreatedKey:
    return await keys.create_key(claims, body)


@admin_router.post("/keys/{key_id}/revoke")
async def revoke_key(key_id: uuid.UUID, claims: AdminSession) -> keys.KeyView:
    return await keys.revoke_key(claims, key_id)


@admin_router.get("/traffic")
async def traffic_summary(
    claims: AdminSession, hours: int = Query(default=24)
) -> list[traffic.EndpointTraffic]:
    if hours not in (1, 24, 48):
        raise UnprocessableError("traffic_hours_invalid", "Choose 1, 24 or 48 hours.")
    return await traffic.summary(get_redis(), hours)
