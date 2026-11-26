"""Active tests on a customer's own site (Phase 5B) against real PostgreSQL + Redis.

By default nothing can start: the founder's go, the final terms and a live OOB are missing.
With every lock opened in the test (never in production config), the scan is queued once per
site, with the customer's consent to exactly the current terms, and the customer can stop it.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import select, update

from guardhub_api.active import kill, owner_scan
from guardhub_api.config import get_settings
from guardhub_api.db.models import ActiveConsent, Module, Project
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.scans.queue import JOBS_STREAM

from .conftest import new_client, signed_in

TERMS = ("2026-12-01", "a" * 64)
CHECKS = ["active_cors", "active_xss"]


async def _site(client: httpx.AsyncClient, *, verified: bool = True) -> str:
    r = await client.post(
        "/api/v1/projects", json={"name": "Mine", "target_url": f"mine-{uuid.uuid4().hex[:6]}.example"}
    )
    project_id = r.json()["id"]
    if verified:
        async with db_session(DbContext.system()) as session:
            await session.execute(
                update(Project).where(Project.id == uuid.UUID(project_id))
                .values(ownership_verified_at=datetime.now(UTC), ownership_method="well_known")
            )  # fmt: skip
    return project_id


async def _open_every_lock(redis: Redis, monkeypatch: pytest.MonkeyPatch) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "customer_active_testing_go", True)
    monkeypatch.setattr(s, "active_tos_version", TERMS[0])
    monkeypatch.setattr(s, "active_tos_sha256", TERMS[1])
    monkeypatch.setattr(s, "active_testing_approved", True)
    info = {"consumer": "test", "active_enabled": True, "active_oob": True}
    await redis.set(owner_scan.SCANNER_INFO_PREFIX + "test", json.dumps(info))
    async with db_session(DbContext.system()) as session:
        await session.execute(update(Module).where(Module.key.in_(CHECKS)).values(enabled_global=True))


@pytest.fixture
async def modules_restored() -> object:
    yield
    async with db_session(DbContext.system()) as session:
        await session.execute(update(Module).where(Module.key.like("active_%")).values(enabled_global=False))


async def _active_jobs(redis: Redis) -> list[dict[str, object]]:
    return [
        j
        for j in (json.loads(f["payload"]) for _, f in await redis.xrange(JOBS_STREAM))
        if j.get("kind") == "active_scan"
    ]


def _body(**kw: object) -> dict[str, object]:
    return {"checks": CHECKS, "exclude": ["/admin"], "terms_version": TERMS[0], "accept_terms": True, **kw}


async def test_off_by_default_nothing_is_queued(client: httpx.AsyncClient, redis: Redis) -> None:
    await signed_in(client)
    project_id = await _site(client)
    r = await client.get(f"/api/v1/projects/{project_id}/active")
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is False
    assert {"customer_go", "terms_final", "oob_live", "approval"} <= set(body["blocked_by"])
    assert "active_idor" not in body["checks"]
    r = await client.post(f"/api/v1/projects/{project_id}/active/scans", json=_body())
    assert r.status_code == 422 and r.json()["error"]["code"] == "customer_active_not_live"
    assert await _active_jobs(redis) == []


async def test_with_every_lock_open_one_scan_per_site_with_consent_and_a_stop(
    client: httpx.AsyncClient, redis: Redis, monkeypatch: pytest.MonkeyPatch, modules_restored: object
) -> None:
    await signed_in(client)
    project_id = await _site(client)
    unverified = await _site(client, verified=False)
    await _open_every_lock(redis, monkeypatch)

    r = await client.get(f"/api/v1/projects/{unverified}/active")
    assert r.json()["blocked_by"] == ["site_verified"]
    assert (await client.post(f"/api/v1/projects/{unverified}/active/scans", json=_body())).status_code == 422

    r = await client.post(f"/api/v1/projects/{project_id}/active/scans", json=_body(accept_terms=False))
    assert r.status_code == 422 and r.json()["error"]["code"] == "terms_not_accepted"
    r = await client.post(f"/api/v1/projects/{project_id}/active/scans", json=_body(terms_version="old"))
    assert r.json()["error"]["code"] == "terms_not_accepted"
    r = await client.post(f"/api/v1/projects/{project_id}/active/scans", json=_body(checks=["active_idor"]))
    assert r.json()["error"]["code"] == "not_a_customer_active_check"

    r = await client.post(f"/api/v1/projects/{project_id}/active/scans", json=_body())
    assert r.status_code == 202, r.text
    scan_id = r.json()["scan_id"]
    [job] = await _active_jobs(redis)
    assert job["scan_id"] == scan_id and job["checks"] == CHECKS and job["exclude"] == ["/admin"]
    assert job["token"]  # the scanner proves ownership again before the first request
    async with db_session(DbContext.system()) as session:
        consent = (await session.execute(select(ActiveConsent).where(ActiveConsent.id == uuid.UUID(str(job["consent_id"]))))).scalar_one()  # fmt: skip
    assert consent.consent_version == f"customer-{TERMS[0]}" and consent.consent_sha256 == TERMS[1]

    r = await client.post(f"/api/v1/projects/{project_id}/active/scans", json=_body())
    assert r.status_code == 409  # one active scan per site
    assert (await client.get(f"/api/v1/projects/{project_id}/active")).json()["running_scan_id"] == scan_id

    async with new_client("198.51.100.91") as stranger:
        await signed_in(stranger)
        r = await stranger.post(f"/api/v1/projects/{project_id}/active/scans/{scan_id}/stop")
        assert r.status_code == 404  # never someone else's site
    assert not (await kill.state(redis, uuid.UUID(scan_id))).engaged
    r = await client.post(f"/api/v1/projects/{project_id}/active/scans/{scan_id}/stop")
    assert r.status_code == 204
    assert (await kill.state(redis, uuid.UUID(scan_id))).engaged


async def test_the_global_kill_switch_still_wins(
    client: httpx.AsyncClient, redis: Redis, monkeypatch: pytest.MonkeyPatch, modules_restored: object
) -> None:
    await signed_in(client)
    project_id = await _site(client)
    await _open_every_lock(redis, monkeypatch)
    await kill.engage(redis, None)
    try:
        r = await client.post(f"/api/v1/projects/{project_id}/active/scans", json=_body())
        assert r.status_code == 422 and "kill" in r.json()["error"]["details"]["blocked_by"]
    finally:
        await kill.release(redis, None)
    assert await _active_jobs(redis) == []
