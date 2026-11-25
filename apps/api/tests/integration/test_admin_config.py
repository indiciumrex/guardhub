"""Admin configuration (Prompt 2 §1) against real PostgreSQL + Redis: bounded changes, audited
history with revert, admin-only, and the flags really gate the public flows."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy import delete, select

from guardhub_api.db.models import AuditLog, PlatformSetting
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.platform import service

from .conftest import new_client, signed_in
from .test_active import make_admin

CONFIG = "/api/v1/admin/config"


@pytest.fixture(autouse=True)
async def clean_settings() -> AsyncIterator[None]:
    """Every test starts and ends with no overrides (the defaults: today's behaviour)."""
    async with db_session(DbContext.system()) as session:
        await session.execute(delete(PlatformSetting))
    service.clear_cache()
    yield
    async with db_session(DbContext.system()) as session:
        await session.execute(delete(PlatformSetting))
    service.clear_cache()


async def test_only_admins_see_or_change_configuration(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    # 404, not 403: the admin surface does not reveal that it exists (auth/deps.py)
    assert (await client.get(CONFIG)).status_code == 404
    r = await client.put(f"{CONFIG}/settings/flags.registration", json={"value": False})
    assert r.status_code == 404
    assert await service.flag("flags.registration") is True
    async with new_client("198.51.100.9") as anon:
        assert (await anon.get(CONFIG)).status_code == 401


async def test_change_reset_and_revert_are_audited(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    view = (await client.get(CONFIG)).json()
    deadline = next(s for s in view["settings"] if s["key"] == "scan.deadline_seconds")
    assert deadline["overridden"] is False and deadline["minimum"] == 30 and deadline["maximum"] == 300

    r = await client.put(
        f"{CONFIG}/settings/scan.deadline_seconds", json={"value": 240, "reason": "slow targets"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["value"] == 240 and r.json()["overridden"] is True
    assert await service.int_value("scan.deadline_seconds") == 240

    r = await client.put(f"{CONFIG}/settings/scan.deadline_seconds", json={"value": 900})
    assert r.status_code == 422 and r.json()["error"]["code"] == "setting_invalid"
    r = await client.put(f"{CONFIG}/settings/active.approved", json={"value": True})
    assert r.status_code == 404 and r.json()["error"]["code"] == "setting_unknown"

    history = (await client.get(CONFIG)).json()["history"]
    change = history[0]
    assert change["action"] == "config.changed" and change["key"] == "scan.deadline_seconds"
    assert change["old"] == "__default__" and change["new"] == "240" and change["reason"] == "slow targets"

    r = await client.post(f"{CONFIG}/history/{change['id']}/revert")
    assert r.status_code == 200, r.text
    assert r.json()["overridden"] is False  # back to the default
    r = await client.post(f"{CONFIG}/settings/scan.deadline_seconds/reset", json={})
    assert r.status_code == 200

    async with db_session(DbContext.system()) as session:
        actions = (
            (
                await session.execute(
                    select(AuditLog.action)
                    .where(AuditLog.target == "scan.deadline_seconds")
                    .order_by(AuditLog.id)
                )
            )
            .scalars()
            .all()
        )
    assert actions[-3:] == ["config.changed", "config.reverted", "config.reset"]


async def test_maintenance_and_flags_gate_the_public_flows(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    async with new_client("198.51.100.21") as anon:
        status = (await anon.get("/api/v1/platform/status")).json()
        assert status == {"maintenance": False, "message": "", "public_scan": True, "registration": True}

        await client.put(f"{CONFIG}/settings/maintenance.message", json={"value": "Back at 14:00 UTC"})
        await client.put(f"{CONFIG}/settings/maintenance.enabled", json={"value": True})
        r = await anon.post("/api/v1/public/challenges", json={"target_url": "my-startup.example"})
        assert r.status_code == 503, r.text
        assert r.json()["error"]["code"] == "maintenance"
        assert r.json()["error"]["details"]["message"] == "Back at 14:00 UTC"
        assert (await anon.get("/api/v1/platform/status")).json()["maintenance"] is True

        await client.put(f"{CONFIG}/settings/maintenance.enabled", json={"value": False})
        await client.put(f"{CONFIG}/settings/flags.public_scan", json={"value": False})
        r = await anon.post("/api/v1/public/challenges", json={"target_url": "my-startup.example"})
        assert r.status_code == 503 and r.json()["error"]["code"] == "public_scan_paused"

        await client.put(f"{CONFIG}/settings/flags.registration", json={"value": False})
        r = await anon.post(
            "/api/v1/auth/register",
            json={"email": "closed@example.com", "password": "a-Strong-passphrase-42", "locale": "en"},
        )
        assert r.status_code == 503 and r.json()["error"]["code"] == "registration_closed"

        await client.post(f"{CONFIG}/settings/flags.public_scan/reset", json={})
        r = await anon.post("/api/v1/public/challenges", json={"target_url": "my-startup.example"})
        assert r.status_code == 201, r.text


async def test_environment_is_read_only_and_masks_secrets(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    env = {e["name"]: e for e in (await client.get(CONFIG)).json()["environment"]}
    assert env["jwt_secret"]["kind"] == "secret" and env["jwt_secret"]["value"] is None
    assert env["database_url"]["kind"] == "secret" and env["database_url"]["value"] is None
    assert env["hash_pepper"]["value"] is None
