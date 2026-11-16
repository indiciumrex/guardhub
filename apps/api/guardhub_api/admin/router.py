"""Admin HTTP routes (docs/architecture.md §4.5): role=admin + MFA, else 404."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel

from guardhub_api.admin import service
from guardhub_api.ai.provider import AIStatus
from guardhub_api.auth.deps import AdminSession
from guardhub_api.health.service import HealthRow
from guardhub_api.modules.registry import ModuleView
from guardhub_api.scans.schemas import ScanSummary

router = APIRouter(prefix="/admin", tags=["admin"])

Limit = Annotated[int, Query(ge=1, le=200)]
Offset = Annotated[int, Query(ge=0, le=100_000)]


class ToggleModuleRequest(BaseModel):
    enabled_global: bool


@router.get("/users")
async def users(claims: AdminSession, limit: Limit = 50, offset: Offset = 0) -> list[service.AdminUserView]:
    return await service.list_users(claims, limit, offset)


@router.get("/scans")
async def scans(claims: AdminSession, limit: Limit = 50, offset: Offset = 0) -> list[ScanSummary]:
    return await service.list_scans(claims, limit, offset)


@router.get("/modules")
async def modules(claims: AdminSession) -> list[ModuleView]:
    return await service.list_modules(claims)


@router.patch("/modules/{key}")
async def toggle_module(key: str, body: ToggleModuleRequest, claims: AdminSession) -> ModuleView:
    return await service.toggle_module(claims, key, body.enabled_global)


@router.get("/health")
async def health(claims: AdminSession) -> list[HealthRow]:
    return await service.latest_health(claims)


@router.get("/audit")
async def audit(claims: AdminSession, limit: Limit = 100) -> list[service.AuditView]:
    return await service.audit_log(claims, limit)


@router.get("/ai")
async def ai(claims: AdminSession) -> AIStatus:
    return service.ai()
