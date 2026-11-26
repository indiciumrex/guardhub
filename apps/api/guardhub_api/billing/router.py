"""Billing routes: the customer's plan and trial, the admin's plans and assignments, and the
provider webhook (signature-verified, no session, refused while charging is off)."""

from __future__ import annotations

import time

from fastapi import APIRouter, Request
from pydantic import BaseModel

from guardhub_api.auth.deps import AdminSession, FullSession
from guardhub_api.billing import service

router = APIRouter(prefix="/billing", tags=["billing"])
admin_router = APIRouter(prefix="/admin/billing", tags=["admin"])


class TrialRequest(BaseModel):
    plan: service.PlanKey


@router.get("")
async def billing(claims: FullSession) -> service.BillingView:
    return await service.view(claims)


@router.post("/trial")
async def start_trial(body: TrialRequest, claims: FullSession) -> service.BillingView:
    return await service.start_trial(claims, body.plan)


@router.post("/webhook/{provider}")
async def webhook(provider: str, request: Request) -> dict[str, str]:
    body = await request.body()
    signature = request.headers.get("stripe-signature", "")
    return {"result": await service.handle_webhook(provider, body, signature, int(time.time()))}


@admin_router.get("")
async def admin_billing(claims: AdminSession) -> service.AdminBillingView:
    return await service.admin_view(claims)


@admin_router.put("/plans/{key}")
async def update_plan(key: str, body: service.UpdatePlan, claims: AdminSession) -> service.PlanView:
    return await service.update_plan(claims, key, body)


@admin_router.post("/subscriptions")
async def assign_plan(body: service.AssignPlan, claims: AdminSession) -> service.AdminSubscription:
    return await service.assign_plan(claims, body)
