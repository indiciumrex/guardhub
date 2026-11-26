"""Billing (Phase 5C) against real PostgreSQL + Redis: today's behaviour by default, plan limits
enforced, one trial per account, a customer can never change their own subscription, and the
provider webhook is refused while charging is off and verified when it is on."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError

from guardhub_api.billing import service
from guardhub_api.config import get_settings
from guardhub_api.db.models import AuditLog, BillingPlan, Module, Scan, Subscription, User
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.scans.service import _within_plan

from .conftest import new_client, signed_in
from .test_active import make_admin

SEED = {
    "free": (25, 1000, 25, 0, True),
    "pro": (25, 1000, 25, 14, False),
    "agency": (25, 1000, 25, 14, False),
}


@pytest.fixture(autouse=True)
async def _restore(redis: Redis) -> AsyncIterator[None]:
    yield
    async with db_session(DbContext.system()) as session:
        for key, (sites, per_day, conc, trial, public) in SEED.items():
            await session.execute(
                update(BillingPlan).where(BillingPlan.key == key).values(
                    max_sites=sites, scans_per_day=per_day, concurrent_scans=conc, trial_days=trial, public=public)
            )  # fmt: skip
        await session.execute(update(Module).values(min_plan="free"))


async def _user_id(email: str) -> uuid.UUID:
    async with db_session(DbContext.system()) as session:
        return (await session.execute(select(User.id).where(User.email == email))).scalar_one()


async def test_defaults_change_nothing_and_charging_is_off(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    body = (await client.get("/api/v1/billing")).json()
    assert body["plan"] == "free" and body["charging_live"] is False
    assert body["limits"]["max_sites"] == 25 and [p["key"] for p in body["plans"]] == ["free"]
    assert body["trial_available"] is False  # no public paid plan yet: the founder decides
    async with new_client("198.51.100.95") as provider:  # no CSRF header, no cookie
        r = await provider.post("/api/v1/billing/webhook/stripe", content=b"{}")
        assert r.status_code == 503 and r.json()["error"]["code"] == "billing_not_live"


async def test_site_limit_and_one_trial_per_account(client: httpx.AsyncClient) -> None:
    email, _ = await signed_in(client)
    async with db_session(DbContext.system()) as session:
        await session.execute(update(BillingPlan).where(BillingPlan.key == "free").values(max_sites=1))
        await session.execute(update(BillingPlan).where(BillingPlan.key == "pro").values(public=True))
    assert (
        await client.post("/api/v1/projects", json={"name": "A", "target_url": "a-plan.example"})
    ).status_code == 201
    r = await client.post("/api/v1/projects", json={"name": "B", "target_url": "b-plan.example"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "plan_limit_sites"

    r = await client.post("/api/v1/billing/trial", json={"plan": "pro"})
    assert r.status_code == 200, r.text
    assert r.json()["plan"] == "pro" and r.json()["status"] == "trialing"
    assert (
        await client.post("/api/v1/projects", json={"name": "B", "target_url": "b-plan.example"})
    ).status_code == 201
    r = await client.post("/api/v1/billing/trial", json={"plan": "pro"})
    assert r.status_code == 422 and r.json()["error"]["code"] == "trial_used"

    assert await service.end_expired_trials(datetime.now(UTC) + timedelta(days=15)) >= 1
    assert (await client.get("/api/v1/billing")).json()["plan"] == "free"
    async with db_session(DbContext.system()) as session:
        actions = set((await session.execute(select(AuditLog.action).where(AuditLog.target == str(await _user_id(email)))))
                      .scalars().all())  # fmt: skip
    assert {"billing.trial_started", "billing.trial_ended"} <= actions


async def test_manual_scan_limits_and_module_tier(client: httpx.AsyncClient) -> None:
    email, _ = await signed_in(client)
    user_id = await _user_id(email)
    async with db_session(DbContext.system()) as session:
        await session.execute(update(BillingPlan).where(BillingPlan.key == "free").values(scans_per_day=1))
        session.add(Scan(user_id=user_id, target_url="https://x.example", trigger="manual", status="done",
                         public_token_hash=hashlib.sha256(uuid.uuid4().bytes).hexdigest()))  # fmt: skip
    async with db_session(DbContext.system()) as session:
        with pytest.raises(Exception, match="daily scan limit"):
            await _within_plan(session, user_id, ["tls_cert"], manual=True)
        # scheduled scans are not counted, only filtered by the module tier
        await session.execute(update(Module).where(Module.key == "tls_cert").values(min_plan="pro"))
        assert await _within_plan(session, user_id, ["tls_cert", "info_leak"], manual=False) == ["info_leak"]


async def test_a_customer_can_never_change_their_own_subscription(client: httpx.AsyncClient) -> None:
    email, _ = await signed_in(client)
    user_id = await _user_id(email)
    with pytest.raises(DBAPIError, match="admin or system context"):
        async with db_session(DbContext(role="user", user_id=user_id)) as session:
            await session.execute(
                text("INSERT INTO subscriptions (user_id, plan, status) VALUES (:u, 'agency', 'active')"),
                {"u": user_id},
            )


async def test_admin_assigns_a_plan_and_edits_limits(client: httpx.AsyncClient) -> None:
    async with new_client("198.51.100.96") as customer:
        email, _ = await signed_in(customer)
    assert await _user_id(email)
    async with new_client("198.51.100.97") as nobody:
        await signed_in(nobody)
        assert (await nobody.get("/api/v1/admin/billing")).status_code == 404
    await make_admin(client)
    r = await client.post(
        "/api/v1/admin/billing/subscriptions", json={"email": email, "plan": "agency", "reason": "invoice 42"}
    )
    assert r.status_code == 200 and r.json()["effective_plan"] == "agency"
    body = {"max_sites": 50, "scans_per_day": 200, "concurrent_scans": 5, "trial_days": 7, "public": True}
    r = await client.put("/api/v1/admin/billing/plans/agency", json=body)
    assert r.status_code == 200 and r.json()["max_sites"] == 50
    assert (
        await client.put("/api/v1/admin/billing/plans/free", json={**body, "public": False})
    ).status_code == 422
    view = (await client.get("/api/v1/admin/billing")).json()
    assert view["charging_live"] is False and view["webhook_secret_configured"] is False


def _signed(secret: str, payload: dict[str, object]) -> tuple[bytes, str]:
    body = json.dumps(payload).encode()
    ts = int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return body, f"t={ts},v1={sig}"


async def test_webhook_verified_applied_once_when_charging_is_on(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    email, _ = await signed_in(client)
    user_id = await _user_id(email)
    s = get_settings()
    monkeypatch.setattr(s, "billing_charging_enabled", True)
    monkeypatch.setattr(s, "billing_provider", "stripe")
    from pydantic import SecretStr

    monkeypatch.setattr(s, "billing_webhook_secret", SecretStr("whsec_test"))
    event = {"id": f"evt_{uuid.uuid4().hex}", "type": "customer.subscription.updated", "data": {"object": {
        "id": "sub_1", "customer": "cus_1", "status": "active",
        "metadata": {"guardhub_user_id": str(user_id), "guardhub_plan": "pro"}}}}  # fmt: skip
    body, sig = _signed("whsec_test", event)
    async with new_client("198.51.100.98") as provider:
        bad = await provider.post(
            "/api/v1/billing/webhook/stripe", content=body, headers={"Stripe-Signature": sig + "0"}
        )
        assert bad.status_code == 422
        r = await provider.post(
            "/api/v1/billing/webhook/stripe", content=body, headers={"Stripe-Signature": sig}
        )
        assert r.status_code == 200 and r.json() == {"result": "ok"}
        again = await provider.post(
            "/api/v1/billing/webhook/stripe", content=body, headers={"Stripe-Signature": sig}
        )
        assert again.json() == {"result": "duplicate"}
    async with db_session(DbContext.system()) as session:
        sub = (
            await session.execute(select(Subscription).where(Subscription.user_id == user_id))
        ).scalar_one()
    assert (sub.plan, sub.status, sub.provider, sub.provider_customer_id) == (
        "pro",
        "active",
        "stripe",
        "cus_1",
    )
