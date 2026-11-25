"""Admin configuration routes (admin only) and the public platform status (no auth)."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel, Field

from guardhub_api.auth.deps import AdminSession
from guardhub_api.platform import service

router = APIRouter(prefix="/admin/config", tags=["admin"])
status_router = APIRouter(prefix="/platform", tags=["public"])


class SetSettingRequest(BaseModel):
    value: int | bool | str
    reason: str = Field(default="", max_length=200)


class ResetSettingRequest(BaseModel):
    reason: str = Field(default="", max_length=200)


@router.get("")
async def config_view(claims: AdminSession) -> service.ConfigView:
    return await service.view(claims)


@router.put("/settings/{key}")
async def set_setting(key: str, body: SetSettingRequest, claims: AdminSession) -> service.SettingView:
    return await service.set_value(claims, key, body.value, body.reason)


@router.post("/settings/{key}/reset")
async def reset_setting(key: str, body: ResetSettingRequest, claims: AdminSession) -> service.SettingView:
    return await service.reset(claims, key, body.reason)


@router.post("/history/{change_id}/revert")
async def revert_change(change_id: int, claims: AdminSession) -> service.SettingView:
    return await service.revert(claims, change_id)


@status_router.get("/status")
async def platform_status() -> service.PlatformStatus:
    return await service.status()
