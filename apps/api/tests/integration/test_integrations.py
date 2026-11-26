"""Integration API keys (Prompt 2 §4) against real PostgreSQL + Redis: shown once and stored
hashed, scoped, expiring, revocable, never a session, the owner's data only, ownership proof
still required to scan; endpoint traffic recorded by route template."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import select, update

from guardhub_api.db.models import ApiKey, AuditLog
from guardhub_api.db.session import DbContext, db_session

from .conftest import new_client, signed_in
from .test_active import make_admin

KEYS = "/api/v1/admin/integrations/keys"
API = "/api/v1/integrations"


def bearer(secret: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {secret}"}


@pytest.fixture(autouse=True)
async def _fresh_rate_limits(redis: Redis) -> AsyncIterator[None]:
    """Every test registers users from the same test address: start each with fresh rate limits."""
    yield


async def _key(client: httpx.AsyncClient, scopes: list[str], days: int = 30) -> tuple[str, str]:
    r = await client.post(KEYS, json={"name": "ci pipeline", "scopes": scopes, "expires_in_days": days})
    assert r.status_code == 201, r.text
    return r.json()["key"]["id"], r.json()["secret"]


async def test_a_key_is_shown_once_and_stored_hashed(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    key_id, secret = await _key(client, ["projects:read"])
    assert secret.startswith("ghk_") and len(secret) == 47
    listed = (await client.get(KEYS)).json()
    row = next(k for k in listed if k["id"] == key_id)
    assert row["prefix"] == secret[:12] and row["status"] == "active"
    assert secret not in str(listed)
    async with db_session(DbContext.system()) as session:
        stored = await session.get(ApiKey, key_id)
        assert stored is not None and stored.key_hash != secret and secret not in stored.key_hash
    r = await client.post(KEYS, json={"name": "x", "scopes": ["projects:read"], "expires_in_days": 400})
    assert r.status_code == 422 and r.json()["error"]["code"] == "api_key_expiry_invalid"
    r = await client.post(KEYS, json={"name": "x", "scopes": ["admin:all"], "expires_in_days": 30})
    assert r.status_code == 422


async def test_scopes_expiry_revocation_and_never_a_session(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    r = await client.post("/api/v1/projects", json={"name": "Own", "target_url": "own-integration.example"})
    project_id = r.json()["id"]
    key_id, secret = await _key(client, ["projects:read", "scans:trigger"])

    async with new_client("198.51.100.41") as tool:  # no cookies: the key is all it has
        r = await tool.get(f"{API}/projects", headers=bearer(secret))
        assert r.status_code == 200, r.text
        assert [p["id"] for p in r.json()] == [project_id]

        r = await tool.get(f"{API}/scans/00000000-0000-0000-0000-000000000000", headers=bearer(secret))
        assert r.status_code == 403 and r.json()["error"]["code"] == "api_key_scope_missing"

        # ownership proof (section 9.2) still applies: the project was never verified
        r = await tool.post(
            f"{API}/projects/{project_id}/scans", headers={**bearer(secret), "X-GuardHub-CSRF": "1"}
        )
        assert r.status_code == 422 and r.json()["error"]["code"] == "ownership_not_verified"

        # an admin-owned key never reaches the admin API
        assert (await tool.get("/api/v1/admin/overview", headers=bearer(secret))).status_code == 401
        assert (await tool.get(KEYS, headers=bearer(secret))).status_code == 401
        assert (await tool.get("/api/v1/auth/me", headers=bearer(secret))).status_code == 401

        assert (await tool.get(f"{API}/projects", headers=bearer("ghk_" + "x" * 43))).status_code == 401
        assert (await tool.get(f"{API}/projects", headers={"Authorization": "Basic abc"})).status_code == 401

        async with db_session(DbContext.system()) as session:
            await session.execute(
                update(ApiKey)
                .where(ApiKey.id == key_id)
                .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )
        r = await tool.get(f"{API}/projects", headers=bearer(secret))
        assert r.status_code == 401 and r.json()["error"]["code"] == "api_key_invalid"

    _, live = await _key(client, ["projects:read"])
    revoke_id = next(k["id"] for k in (await client.get(KEYS)).json() if k["prefix"] == live[:12])
    assert (await client.post(f"{KEYS}/{revoke_id}/revoke")).json()["status"] == "revoked"
    async with new_client("198.51.100.42") as tool:
        assert (await tool.get(f"{API}/projects", headers=bearer(live))).status_code == 401

    async with db_session(DbContext.system()) as session:
        actions = set(
            (await session.execute(select(AuditLog.action).where(AuditLog.action.like("api_key.%"))))
            .scalars()
            .all()
        )
    assert {"api_key.created", "api_key.revoked"} <= actions


async def test_a_key_sees_only_its_owners_data(client: httpx.AsyncClient) -> None:
    async with new_client("198.51.100.43") as other:
        await signed_in(other)
        r = await other.post("/api/v1/projects", json={"name": "Theirs", "target_url": "theirs.example"})
        theirs = r.json()["id"]
    await make_admin(client)
    _, secret = await _key(client, ["projects:read"])
    async with new_client("198.51.100.44") as tool:
        ids = [p["id"] for p in (await tool.get(f"{API}/projects", headers=bearer(secret))).json()]
    assert theirs not in ids  # admin-owned key, user role: no platform-wide view


async def test_admin_only_and_traffic_by_route_template(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    assert (await client.get(KEYS)).status_code == 404
    assert (await client.get("/api/v1/admin/integrations/traffic")).status_code == 404
    await make_admin(client)
    _, secret = await _key(client, ["scans:read"])
    async with new_client("198.51.100.45") as tool:
        await tool.get(f"{API}/scans/11111111-1111-1111-1111-111111111111", headers=bearer(secret))
    rows = (await client.get("/api/v1/admin/integrations/traffic?hours=1")).json()
    endpoints = {r["endpoint"]: r for r in rows}
    hit = endpoints["GET /api/v1/integrations/scans/{scan_id}"]
    assert hit["requests"] >= 1 and hit["client_errors"] >= 1
    assert not any("11111111" in e for e in endpoints)  # templates, never raw identifiers
