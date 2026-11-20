"""Notification settings routes (docs/architecture.md §8.4). Full MFA session; own data only."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, status

from guardhub_api.alerts import service
from guardhub_api.alerts.repository import HistoryFilter
from guardhub_api.alerts.schemas import (
    NotificationHistoryItem,
    NotificationSettingsView,
    TestNotificationQueued,
    TestNotificationRequest,
    UpdateNotificationSettings,
)
from guardhub_api.auth.deps import FullSession
from guardhub_api.common.redis import get_redis

router = APIRouter(prefix="/account/notifications", tags=["notifications"])


@router.get("")
async def get_settings(claims: FullSession) -> NotificationSettingsView:
    return await service.get_view(claims)


@router.put("")
async def put_settings(body: UpdateNotificationSettings, claims: FullSession) -> NotificationSettingsView:
    return await service.update(claims, body)


@router.post("/test", status_code=status.HTTP_202_ACCEPTED)
async def send_test(body: TestNotificationRequest, claims: FullSession) -> TestNotificationQueued:
    await service.request_test(get_redis(), claims, body.channel)
    return TestNotificationQueued()


@router.get("/history")
async def get_history(
    claims: FullSession,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    show: Annotated[HistoryFilter, Query()] = "alerts",
) -> list[NotificationHistoryItem]:
    """`show`: "alerts" (default: real alerts only), "test" (test messages only) or "all"."""
    return await service.history(claims, limit, show)
