"""Admin routes for operational alerts (admin only, every change audited)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter
from pydantic import BaseModel

from guardhub_api.auth.deps import AdminSession
from guardhub_api.opsalerts import service

router = APIRouter(prefix="/admin/alerts", tags=["admin"])


class MuteRequest(BaseModel):
    minutes: int


@router.get("")
async def alerts_view(claims: AdminSession) -> service.AlertsView:
    return await service.view(claims)


@router.post("/{alert_id}/acknowledge")
async def acknowledge(alert_id: uuid.UUID, claims: AdminSession) -> service.AlertView:
    return await service.acknowledge(claims, alert_id)


@router.post("/{alert_id}/resolve")
async def resolve(alert_id: uuid.UUID, claims: AdminSession) -> service.AlertView:
    return await service.resolve(claims, alert_id)


@router.put("/rules/{kind}")
async def update_rule(kind: str, body: service.UpdateRule, claims: AdminSession) -> service.RuleView:
    return await service.update_rule(claims, kind, body)


@router.post("/rules/{kind}/mute")
async def mute(kind: str, body: MuteRequest, claims: AdminSession) -> service.RuleView:
    return await service.mute(claims, kind, body.minutes)
