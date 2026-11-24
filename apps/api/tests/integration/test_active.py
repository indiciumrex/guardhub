"""Phase 4B active-testing safety (ADR-0008) against real PostgreSQL (RLS, triggers) + Redis.

Rules under test: active modules ship off and cannot be switched on before the founder's
checkpoint; the request log is append-only and stored once per scan; a consent can only be
revoked, never rewritten or deleted; the kill switch is set before it is audited and released
only after.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from guardhub_api.admin.bootstrap import _set_role
from guardhub_api.db.models import ActiveConsent, ActiveRequestLog, AuditLog, Module, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.contract_gen import ACTIVE_CHECK_IDS
from guardhub_api.scans.ingest import handle_event

from .conftest import signed_in

ADMIN = "/api/v1/admin"


async def make_admin(client: httpx.AsyncClient) -> str:
    email, _ = await signed_in(client)
    assert await _set_role(email, "admin") == 0
    return email


async def new_scan() -> uuid.UUID:
    async with db_session(DbContext.system()) as session:
        scan = Scan(
            target_url="https://example.com", public_token_hash=hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        )
        session.add(scan)
        await session.flush()
        return scan.id


def log_event(scan_id: uuid.UUID, consent_id: uuid.UUID, n: int = 3) -> dict[str, object]:
    entries = [
        {
            "at": "2026-11-24T05:00:00.123456789Z",
            "module": "active_xss",
            "payload_id": "xss.marker.tag",
            "payload_sha256": "a" * 64,
            "method": "GET",
            "path": f"/p{i}",
            "param": "q",
            "status": 200,
            "length": 10,
            "latency_ms": 5,
            "outcome": "sent",
        }
        for i in range(n)
    ]
    entries.append({**entries[0], "method": "POST"})  # never stored: active tests are GET-only
    return {"v": 1, "type": "active.request_log", "scan_id": str(scan_id), "consent_id": str(consent_id),
            "at": datetime.now(UTC).isoformat(), "entries": entries}  # fmt: skip


async def test_active_modules_ship_off_and_stay_off(client: httpx.AsyncClient) -> None:
    async with db_session(DbContext.system()) as session:
        rows = (await session.execute(select(Module).where(Module.key.in_(ACTIVE_CHECK_IDS)))).scalars().all()
    assert {m.key for m in rows} == set(ACTIVE_CHECK_IDS)
    assert not any(m.enabled_global for m in rows)
    await make_admin(client)
    r = await client.patch(f"{ADMIN}/modules/active_xss", json={"enabled_global": True})
    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] == "active_testing_not_approved"
    r = await client.get("/api/v1/checks")
    assert r.status_code == 200
    assert not {c["id"] for c in r.json()} & set(ACTIVE_CHECK_IDS)


async def test_request_log_stored_once_and_append_only(redis: Redis) -> None:
    scan_id, consent_id = await new_scan(), uuid.uuid4()
    event = log_event(scan_id, consent_id)
    await handle_event(redis, event)
    await handle_event(redis, event)  # redelivered: not stored twice
    async with db_session(DbContext.system()) as session:
        rows = (
            (await session.execute(select(ActiveRequestLog).where(ActiveRequestLog.scan_id == scan_id)))
            .scalars()
            .all()
        )
    assert len(rows) == 3
    assert all(r.method == "GET" for r in rows)
    assert rows[0].at.microsecond == 123456  # Go's nanoseconds parsed, not replaced by now()
    for stmt in ("UPDATE active_request_log SET path = '/x' WHERE scan_id = :s",
                 "DELETE FROM active_request_log WHERE scan_id = :s"):  # fmt: skip
        # the app role has no UPDATE/DELETE grant at all; the append-only trigger is a 2nd layer
        with pytest.raises(DBAPIError, match=r"permission denied|append-only"):
            async with db_session(DbContext.system()) as session:
                await session.execute(text(stmt), {"s": scan_id})


async def test_consent_can_only_be_revoked() -> None:
    async with db_session(DbContext.system()) as session:
        consent = ActiveConsent(origin="https://example.com", checks=["active_xss"], consent_version="draft-0",
                                consent_sha256="b" * 64)  # fmt: skip
        session.add(consent)
        await session.flush()
        cid = consent.id
    async with db_session(DbContext.system()) as session:
        await session.execute(text("UPDATE active_consents SET revoked_at = now() WHERE id = :i"), {"i": cid})
    for stmt in ("UPDATE active_consents SET origin = 'https://evil.example' WHERE id = :i",
                 "UPDATE active_consents SET revoked_at = NULL WHERE id = :i",
                 "DELETE FROM active_consents WHERE id = :i"):  # fmt: skip
        with pytest.raises(DBAPIError):
            async with db_session(DbContext.system()) as session:
                await session.execute(text(stmt), {"i": cid})


async def test_kill_switch_engage_and_release(client: httpx.AsyncClient, redis: Redis) -> None:
    await make_admin(client)
    scan_id = uuid.uuid4()
    r = await client.post(f"{ADMIN}/active/kill", json={"engaged": True})
    assert r.status_code == 200, r.text
    assert await redis.exists("gh:active:kill") == 1
    r = await client.post(f"{ADMIN}/active/kill", json={"engaged": True, "scan_id": str(scan_id)})
    assert await redis.exists(f"gh:active:kill:{scan_id}") == 1
    r = await client.get(f"{ADMIN}/active/kill")
    assert r.json() == {"scope": "global", "engaged": True}
    r = await client.post(f"{ADMIN}/active/kill", json={"engaged": False})
    assert r.status_code == 200
    assert await redis.exists("gh:active:kill") == 0
    assert await redis.exists(f"gh:active:kill:{scan_id}") == 1  # releasing all does not touch one scan's key
    async with db_session(DbContext.system()) as session:
        actions = (
            (
                await session.execute(
                    select(AuditLog.action).where(AuditLog.action.in_(["active.kill", "active.unkill"]))
                )
            )
            .scalars()
            .all()
        )
    assert actions.count("active.kill") >= 2 and actions.count("active.unkill") >= 1


async def test_kill_switch_is_admin_only(client: httpx.AsyncClient, redis: Redis) -> None:
    await signed_in(client)
    r = await client.post(f"{ADMIN}/active/kill", json={"engaged": True})
    assert r.status_code == 404
    assert await redis.exists("gh:active:kill") == 0
