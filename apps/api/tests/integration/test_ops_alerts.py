"""Admin operational alerts (Prompt 2 §2) against real PostgreSQL + Redis: one alert per kind
while the condition holds, auto-resolve, one opening mail, mute, escalation, admin actions."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import delete, select, update

from guardhub_api.db.models import AuditLog, OpsAlert, OpsAlertRule, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.opsalerts import counters, service

from .conftest import signed_in
from .test_active import make_admin

ALERTS = "/api/v1/admin/alerts"
DEFAULTS = {
    "critical_finding": (1, 60, None),
    "scan_failures": (5, 30, 60),
    "worker_offline": (5, 5, 30),
    "api_errors": (20, 15, 60),
}


async def _set_rule(kind: str, **values: object) -> None:
    async with db_session(DbContext.system()) as session:
        await session.execute(update(OpsAlertRule).where(OpsAlertRule.kind == kind).values(**values))


async def _only(kind: str, *, threshold: int, window: int = 30, escalate: int | None = None) -> None:
    """Switch every rule off except `kind` (other tests share the database)."""
    async with db_session(DbContext.system()) as session:
        await session.execute(update(OpsAlertRule).values(enabled=False))
    await _set_rule(
        kind,
        enabled=True,
        threshold=threshold,
        window_minutes=window,
        email=True,
        muted_until=None,
        escalate_after_minutes=escalate,
    )


@pytest.fixture(autouse=True)
async def clean() -> AsyncIterator[None]:
    async with db_session(DbContext.system()) as session:
        await session.execute(delete(OpsAlert))
    yield
    async with db_session(DbContext.system()) as session:
        await session.execute(delete(OpsAlert))
    for kind, (threshold, window, escalate) in DEFAULTS.items():
        await _set_rule(
            kind,
            enabled=True,
            threshold=threshold,
            window_minutes=window,
            email=True,
            muted_until=None,
            escalate_after_minutes=escalate,
        )


async def _failed_scans(n: int) -> None:
    async with db_session(DbContext.system()) as session:
        for _ in range(n):
            session.add(
                Scan(
                    target_url="https://example.com",
                    status="failed",
                    error="internal",
                    public_token_hash=f"ops-alert-{uuid.uuid4().hex}",
                    finished_at=datetime.now(UTC),
                )
            )


async def _alerts(kind: str) -> list[OpsAlert]:
    async with db_session(DbContext.system()) as session:
        return list((await session.execute(select(OpsAlert).where(OpsAlert.kind == kind))).scalars().all())


async def test_one_alert_while_the_condition_holds_then_auto_resolve(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    await make_admin(client)  # at least one admin to mail
    await _only("scan_failures", threshold=2, escalate=60)
    await _failed_scans(3)
    first = await service.evaluate(redis)
    assert first["opened"] == 1
    await service.evaluate(redis)  # still breaching: updated, not opened again
    [alert] = await _alerts("scan_failures")
    assert alert.status == "open"
    assert alert.value >= 3
    assert alert.threshold == 2
    # SMTP is not configured in tests: one attempt, recorded on the alert, never retried
    assert alert.emailed_at is not None
    assert alert.detail.get("email_error")
    emailed = alert.emailed_at
    await service.evaluate(redis)
    assert (await _alerts("scan_failures"))[0].emailed_at == emailed

    # nobody acknowledged it within 60 minutes: one escalation (the failures stay in the window)
    await _set_rule("scan_failures", window_minutes=120)
    await service.evaluate(redis, now=datetime.now(UTC) + timedelta(minutes=61))
    assert (await _alerts("scan_failures"))[0].escalated_at is not None

    await _set_rule("scan_failures", threshold=1000)  # the condition clears
    report = await service.evaluate(redis)
    assert report["resolved"] == 1
    [alert] = await _alerts("scan_failures")
    assert alert.status == "resolved"
    assert alert.resolved_by is None  # resolved automatically


async def test_muted_rule_records_in_app_but_sends_nothing(redis: Redis) -> None:
    await _only("api_errors", threshold=2, window=5)
    await _set_rule("api_errors", muted_until=datetime.now(UTC) + timedelta(hours=1))
    for _ in range(3):
        await counters.count_5xx(redis)
    await service.evaluate(redis)
    [alert] = await _alerts("api_errors")
    assert alert.status == "open"
    assert alert.emailed_at is None


async def test_scanner_offline_for_minutes(redis: Redis) -> None:
    await _only("worker_offline", threshold=5, window=5)
    await redis.delete(service.SCANNER_DOWN_KEY)
    now = datetime.now(UTC)
    await service.evaluate(redis, now=now)  # no scanner consumer in tests: down from now on
    assert await _alerts("worker_offline") == []
    await service.evaluate(redis, now=now + timedelta(minutes=6))
    [alert] = await _alerts("worker_offline")
    assert alert.value >= 5
    await redis.delete(service.SCANNER_DOWN_KEY)


async def test_admin_actions_are_admin_only_and_audited(client: httpx.AsyncClient, redis: Redis) -> None:
    await signed_in(client)
    assert (await client.get(ALERTS)).status_code == 404  # the admin surface stays hidden
    await make_admin(client)
    await _only("scan_failures", threshold=1)
    await _failed_scans(1)
    await service.evaluate(redis)

    view = (await client.get(ALERTS)).json()
    assert [r["kind"] for r in view["rules"]] == [
        "critical_finding",
        "scan_failures",
        "worker_offline",
        "api_errors",
    ]
    [alert] = view["open"]
    r = await client.post(f"{ALERTS}/{alert['id']}/acknowledge")
    assert r.status_code == 200
    assert r.json()["status"] == "acknowledged"
    r = await client.post(f"{ALERTS}/{alert['id']}/resolve")
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"
    assert (await client.post(f"{ALERTS}/{alert['id']}/resolve")).status_code == 422

    body: dict[str, object] = {
        "enabled": True,
        "threshold": 0,
        "window_minutes": 30,
        "email": True,
        "escalate_after_minutes": None,
    }
    assert (await client.put(f"{ALERTS}/rules/scan_failures", json=body)).status_code == 422
    body["threshold"] = 3
    r = await client.put(f"{ALERTS}/rules/scan_failures", json=body)
    assert r.status_code == 200
    assert r.json()["threshold"] == 3
    assert (await client.post(f"{ALERTS}/rules/scan_failures/mute", json={"minutes": 7})).status_code == 422
    r = await client.post(f"{ALERTS}/rules/scan_failures/mute", json={"minutes": 60})
    assert r.status_code == 200
    assert r.json()["muted_until"] is not None
    assert (await client.put(f"{ALERTS}/rules/nope", json=body)).status_code == 404

    async with db_session(DbContext.system()) as session:
        rows = await session.execute(select(AuditLog.action).where(AuditLog.action.like("ops_alert%")))
        actions = set(rows.scalars().all())
    assert {
        "ops_alert.opened",
        "ops_alert.acknowledged",
        "ops_alert.resolved",
        "ops_alert_rule.changed",
        "ops_alert_rule.muted",
    } <= actions


async def test_api_5xx_responses_are_counted(redis: Redis) -> None:
    before = await counters.errors_in_window(redis, 1)
    await counters.count_5xx(redis)
    assert await counters.errors_in_window(redis, 1) == before + 1
