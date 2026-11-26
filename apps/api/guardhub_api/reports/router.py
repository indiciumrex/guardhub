"""Admin report routes (admin only). Exports are audited; customer data is always masked."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Query, Response
from pydantic import BaseModel

from guardhub_api.auth.deps import AdminSession
from guardhub_api.reports import service

router = APIRouter(prefix="/admin/reports", tags=["admin"])
schedules_router = APIRouter(prefix="/admin/report-schedules", tags=["admin"])


class ScheduleRequest(BaseModel):
    enabled: bool


@router.get("/{kind}", response_model=None)
async def report(
    kind: str,
    claims: AdminSession,
    days: int = Query(default=30),
    format: Literal["json", "csv", "xlsx"] = Query(default="json"),
) -> service.ReportView | Response:
    if format == "json":
        return await service.preview(claims, kind, days)
    content, media, name = await service.export(claims, kind, days, format)
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"},
    )


@schedules_router.get("")
async def schedules(claims: AdminSession) -> list[service.ScheduleView]:
    return await service.schedules(claims)


@schedules_router.put("/{frequency}")
async def set_schedule(frequency: str, body: ScheduleRequest, claims: AdminSession) -> service.ScheduleView:
    return await service.set_schedule(claims, frequency, body.enabled)
