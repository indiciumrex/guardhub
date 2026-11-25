"""Signed webhooks (Prompt 2 §4) against real PostgreSQL + Redis: secret shown once and stored
encrypted, unsafe URLs refused, scan events only to the scan owner's webhooks, delivery outcomes
recorded without the payload, admin only. The network call itself is replaced in these tests."""

from __future__ import annotations

import hashlib
import uuid

import httpx
import pytest
from sqlalchemy import select

from guardhub_api.db.models import AuditLog, Scan, User, Webhook, WebhookDelivery
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.webhooks import service
from guardhub_api.webhooks.safety import UnsafeWebhookError, verify

from .conftest import new_client, signed_in
from .test_active import make_admin

HOOKS = "/api/v1/admin/webhooks"


async def _hook(client: httpx.AsyncClient, events: list[str]) -> tuple[str, str]:
    r = await client.post(HOOKS, json={"name": "ci", "url": "https://hooks.example.com/in", "events": events})
    assert r.status_code == 201, r.text
    return r.json()["webhook"]["id"], r.json()["secret"]


async def _scan_for(email: str) -> uuid.UUID:
    async with db_session(DbContext.system()) as session:
        user_id = (await session.execute(select(User.id).where(User.email == email))).scalar_one()
        scan = Scan(target_url="https://own.example", user_id=user_id, status="done", score=90,
                    public_token_hash=hashlib.sha256(uuid.uuid4().bytes).hexdigest())  # fmt: skip
        session.add(scan)
        await session.flush()
        return scan.id


async def _ping(hook_id: str) -> uuid.UUID:
    """A ping fanned out to every ping webhook; this test's own delivery (other tests leave hooks)."""
    created = await service.fan_out("ping", f"ping:{uuid.uuid4()}")
    async with db_session(DbContext.system()) as session:
        return (
            await session.execute(
                select(WebhookDelivery.id).where(
                    WebhookDelivery.id.in_(created), WebhookDelivery.webhook_id == uuid.UUID(hook_id)
                )
            )
        ).scalar_one()


async def test_secret_once_encrypted_and_unsafe_urls_refused(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    hook_id, secret = await _hook(client, ["ping"])
    assert secret.startswith("whsec_")
    assert secret not in str((await client.get(HOOKS)).json())
    async with db_session(DbContext.system()) as session:
        stored = await session.get(Webhook, uuid.UUID(hook_id))
        assert stored is not None and secret not in stored.secret_enc
    for url in ("http://hooks.example.com/in", "https://10.0.0.5/in", "https://hooks.example.com:8443/in",
                "https://metadata.google.internal/x"):  # fmt: skip
        r = await client.post(HOOKS, json={"name": "x", "url": url, "events": ["ping"]})
        assert r.status_code == 422 and r.json()["error"]["code"] == "webhook_url_invalid", url


async def test_scan_events_reach_only_the_scan_owners_webhooks(client: httpx.AsyncClient) -> None:
    admin_email = await make_admin(client)
    hook_id, _ = await _hook(client, ["scan.completed"])
    async with new_client("198.51.100.51") as other:
        other_email, _ = await signed_in(other)
    own = await service.fan_out("scan.completed", str(await _scan_for(admin_email)))
    theirs = await service.fan_out("scan.completed", str(await _scan_for(other_email)))
    async with db_session(DbContext.system()) as session:
        hooks = {
            d.webhook_id for d in (await session.execute(select(WebhookDelivery).where(WebhookDelivery.id.in_(own))))
            .scalars().all()
        }  # fmt: skip
    assert uuid.UUID(hook_id) in hooks
    async with db_session(DbContext.system()) as session:
        leaked = (
            await session.execute(
                select(WebhookDelivery).where(WebhookDelivery.id.in_(theirs), WebhookDelivery.webhook_id == uuid.UUID(hook_id))
            )
        ).scalars().all()  # fmt: skip
    assert leaked == []


async def test_delivery_outcomes_are_recorded_without_the_payload(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_admin(client)
    hook_id, secret = await _hook(client, ["ping"])
    sent: list[tuple[bytes, dict[str, str]]] = []

    async def ok(url: str, body: bytes, headers: dict[str, str]) -> int:
        sent.append((body, headers))
        return 204

    monkeypatch.setattr(service, "_post", ok)
    first = await _ping(hook_id)
    assert await service.deliver(first, final_try=False) == "sent"
    body, headers = sent[0]
    assert verify(secret, body, headers["X-GuardHub-Signature"], now=int(__import__("time").time()))
    assert headers["X-GuardHub-Event"] == "ping"

    async def unavailable(url: str, body: bytes, headers: dict[str, str]) -> int:
        return 503

    monkeypatch.setattr(service, "_post", unavailable)
    second = await _ping(hook_id)
    assert await service.deliver(second, final_try=False) == "retry"
    assert await service.deliver(second, final_try=True) == "failed"

    async def blocked(url: str, body: bytes, headers: dict[str, str]) -> int:
        raise UnsafeWebhookError("blocked_address")

    monkeypatch.setattr(service, "_post", blocked)
    third = await _ping(hook_id)
    assert await service.deliver(third, final_try=False) == "failed"  # never retried

    async with db_session(DbContext.system()) as session:
        rows = {d.id: d for d in (await session.execute(select(WebhookDelivery))).scalars().all()}
    assert rows[first].status == "sent" and rows[first].http_status == 204
    assert rows[first].payload_sha256 == hashlib.sha256(body).hexdigest()
    assert rows[second].status == "failed" and rows[second].attempts == 2 and rows[second].error == "http_503"
    assert rows[third].status == "failed" and rows[third].error == "blocked_address"

    view = next(w for w in (await client.get(HOOKS)).json() if w["id"] == hook_id)
    assert {d["status"] for d in view["deliveries"]} >= {"sent", "failed"}

    r = await client.post(f"{HOOKS}/{hook_id}/enabled", json={"enabled": False})
    assert r.status_code == 200 and r.json()["enabled"] is False
    assert (await client.post(f"{HOOKS}/{hook_id}/ping")).status_code == 422
    async with db_session(DbContext.system()) as session:
        actions = set(
            (await session.execute(select(AuditLog.action).where(AuditLog.action.like("webhook.%"))))
            .scalars()
            .all()
        )
    assert {"webhook.created", "webhook.disabled"} <= actions


async def test_webhooks_are_admin_only(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    assert (await client.get(HOOKS)).status_code == 404
    r = await client.post(
        HOOKS, json={"name": "x", "url": "https://hooks.example.com/in", "events": ["ping"]}
    )
    assert r.status_code == 404
