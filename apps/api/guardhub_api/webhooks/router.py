"""Admin webhook routes (admin only; every change audited)."""

from __future__ import annotations

import uuid

from fastapi import APIRouter
from pydantic import BaseModel

from guardhub_api.auth.deps import AdminSession
from guardhub_api.webhooks import service

router = APIRouter(prefix="/admin/webhooks", tags=["admin"])


class EnableRequest(BaseModel):
    enabled: bool


@router.get("")
async def list_webhooks(claims: AdminSession) -> list[service.WebhookView]:
    return await service.list_webhooks(claims)


@router.post("", status_code=201)
async def create_webhook(body: service.CreateWebhookRequest, claims: AdminSession) -> service.CreatedWebhook:
    return await service.create_webhook(claims, body)


@router.post("/{webhook_id}/enabled")
async def set_enabled(
    webhook_id: uuid.UUID, body: EnableRequest, claims: AdminSession
) -> service.WebhookView:
    return await service.set_enabled(claims, webhook_id, body.enabled)


@router.post("/{webhook_id}/ping", status_code=202)
async def ping(webhook_id: uuid.UUID, claims: AdminSession) -> service.DeliveryView:
    return await service.ping(claims, webhook_id)
