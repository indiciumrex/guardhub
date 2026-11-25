"""Admin HTTP routes (docs/architecture.md §4.5): role=admin + MFA, else 404."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field

from guardhub_api.active import owner_scan
from guardhub_api.active.kill import KillState
from guardhub_api.admin import center, service
from guardhub_api.ai.provider import AIStatus
from guardhub_api.auth.deps import AdminSession
from guardhub_api.common.redis import get_redis
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
async def audit(
    claims: AdminSession,
    *,
    limit: Limit = 100,
    offset: Offset = 0,
    action: Annotated[str | None, Query(max_length=64)] = None,
    actor: Annotated[str | None, Query(max_length=128)] = None,
    target: Annotated[str | None, Query(max_length=256)] = None,
) -> list[center.AuditDetail]:
    """Newest first; `action` is a prefix (e.g. "module."), actor and target are exact."""
    return await center.audit_log(
        claims, limit=limit, offset=offset, action=action, actor=actor, target=target
    )


class ActiveKillRequest(BaseModel):
    engaged: bool
    scan_id: uuid.UUID | None = None  # None: every active scan


@router.get("/active/kill")
async def active_kill_state(claims: AdminSession, scan_id: uuid.UUID | None = None) -> KillState:
    return await service.active_kill_state(scan_id)


@router.post("/active/kill")
async def active_kill(body: ActiveKillRequest, claims: AdminSession) -> KillState:
    """The active-test kill switch (ADR-0008 §3): stops every active request within ~1 s."""
    return await service.set_active_kill(claims, engaged=body.engaged, scan_id=body.scan_id)


@router.get("/active/owner-scan")
async def owner_scan_readiness(claims: AdminSession) -> owner_scan.OwnerScanReadiness:
    """What still blocks an active scan of a GuardHub-owned target (the four locks + a target)."""
    return await owner_scan.readiness(claims, get_redis())


@router.post("/active/owner-scan", status_code=202)
async def start_owner_scan(
    body: owner_scan.OwnerScanRequest, claims: AdminSession
) -> owner_scan.OwnerScanStarted:
    """Active checks on an admin trusted domain (owned, proven), only when every lock allows it."""
    return await owner_scan.start(claims, get_redis(), body)


@router.get("/ai")
async def ai(claims: AdminSession) -> AIStatus:
    return service.ai()


# ---- admin control centre (GUARDHUB_STANDARDS §8.3) ----

Locale = Annotated[str, Query(pattern=r"^[A-Za-z-]{2,8}$")]
Lifecycle = Annotated[str | None, Query(pattern=r"^(queued|running|completed|failed|timed_out|cancelled)$")]


class ModuleConfigRequest(BaseModel):
    maintenance: bool | None = None
    min_plan: str | None = Field(default=None, max_length=16)


class TriageRequest(BaseModel):
    status: str = Field(max_length=32)
    note: str = Field(default="", max_length=500)


@router.get("/overview")
async def overview(claims: AdminSession) -> center.OverviewView:
    return await center.overview(claims, get_redis())


@router.get("/modules/stats")
async def module_stats(claims: AdminSession) -> list[center.ModuleStats]:
    return await center.module_stats(claims)


@router.patch("/modules/{key}/config")
async def module_config(key: str, body: ModuleConfigRequest, claims: AdminSession) -> ModuleView:
    return await service.module_config(claims, key, maintenance=body.maintenance, min_plan=body.min_plan)


@router.get("/modules/{key}/changelog")
async def module_changelog(key: str, claims: AdminSession) -> list[center.AuditDetail]:
    return await center.module_changelog(claims, key)


@router.get("/orchestration")
async def orchestration(claims: AdminSession) -> center.OrchestrationView:
    return await center.orchestration(claims, get_redis())


@router.get("/scans/detailed")
async def scans_detailed(
    claims: AdminSession, stage: Lifecycle = None, limit: Limit = 50, offset: Offset = 0
) -> list[center.AdminScanView]:
    return await center.list_scans(claims, stage=stage, limit=limit, offset=offset)


@router.get("/scans/{scan_id}")
async def scan_detail(scan_id: uuid.UUID, claims: AdminSession) -> center.AdminScanView:
    return await center.get_scan(claims, scan_id)


@router.post("/scans/{scan_id}/cancel")
async def scan_cancel(scan_id: uuid.UUID, claims: AdminSession) -> center.AdminScanView:
    return await center.cancel_scan(claims, get_redis(), scan_id)


@router.post("/scans/{scan_id}/rerun")
async def scan_rerun(scan_id: uuid.UUID, claims: AdminSession) -> center.AdminScanView:
    return await center.rerun_scan(claims, get_redis(), scan_id)


@router.get("/scans/{scan_id}/risk")
async def scan_risk(scan_id: uuid.UUID, claims: AdminSession, locale: Locale = "en") -> center.RiskView:
    return await center.scan_risk(claims, scan_id, locale)


@router.get("/findings")
async def findings(
    claims: AdminSession,
    *,
    severity: Annotated[str | None, Query(pattern=r"^(critical|high|medium|low|info)$")] = None,
    check_id: Annotated[str | None, Query(max_length=64)] = None,
    triage: Annotated[str | None, Query(pattern=r"^(new|verified|accepted|false_positive|resolved)$")] = None,
    limit: Limit = 50,
    offset: Offset = 0,
    locale: Locale = "en",
) -> list[center.FindingGroupView]:
    return await center.list_findings(
        claims, severity=severity, check_id=check_id, triage=triage, limit=limit, offset=offset, locale=locale
    )


@router.put("/findings/{fingerprint}/triage")
async def finding_triage(
    fingerprint: Annotated[str, Field(max_length=128)], body: TriageRequest, claims: AdminSession
) -> center.TriageView:
    return await center.set_triage(claims, fingerprint, body.status, body.note)


@router.get("/monitoring")
async def monitoring(claims: AdminSession) -> center.MonitoringView:
    return await center.monitoring(claims, get_redis())
