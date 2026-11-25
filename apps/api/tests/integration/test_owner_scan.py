"""Owner-target active scans (ADR-0008 §8, founder 2026-11-25) against real PostgreSQL + Redis.

Every lock must hold, in order: founder approval, the requested modules on, the kill switch
released, a scanner with SCANNER_ACTIVE_ENABLED, an active admin trusted domain; then one active
scan per origin. Only then is an active_scan job queued, with a consent row and an audit row.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import select, update

from guardhub_api.active import owner_scan
from guardhub_api.config import get_settings
from guardhub_api.db.models import ActiveConsent, AdminTrustedDomain, AuditLog, Module, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.scans.ingest import handle_event
from guardhub_api.scans.queue import JOBS_STREAM

from .test_active import ADMIN, make_admin

FIVE = ["active_cors", "active_idor", "active_redirect", "active_sqli", "active_xss"]


async def _set_modules(keys: list[str], on: bool) -> None:
    async with db_session(DbContext.system()) as session:
        await session.execute(update(Module).where(Module.key.in_(keys)).values(enabled_global=on))


@pytest.fixture
async def modules_restored() -> AsyncIterator[None]:
    """Active modules ship off; whatever a test switched on is switched off again."""
    yield
    await _set_modules([*FIVE, "active_ssrf"], on=False)


async def _domain(client: httpx.AsyncClient, status: str = "active") -> uuid.UUID:
    me = (await client.get("/api/v1/auth/me")).json()
    host = f"own-{uuid.uuid4().hex[:8]}.example"
    async with db_session(DbContext.system()) as session:
        d = AdminTrustedDomain(
            admin_user_id=uuid.UUID(me["id"]),
            host=host,
            target_origin=f"https://{host}",
            status=status,
            verification_token="ghv_owner-test-token",
            method="well_known",
            verified_at=datetime.now(UTC),
        )
        session.add(d)
        await session.flush()
        return d.id


async def _scanner_on(redis: Redis, *, oob: bool = False) -> None:
    info = {"consumer": "test", "active_enabled": True, "active_oob": oob}
    await redis.set(owner_scan.SCANNER_INFO_PREFIX + "test", json.dumps(info))


async def _active_jobs(redis: Redis) -> list[dict[str, object]]:
    jobs = [json.loads(f["payload"]) for _, f in await redis.xrange(JOBS_STREAM)]
    return [j for j in jobs if j.get("kind") == "active_scan"]


def _code(r: httpx.Response) -> str:
    return str(r.json()["error"]["code"])


async def test_every_lock_must_allow_it(
    client: httpx.AsyncClient, redis: Redis, monkeypatch: pytest.MonkeyPatch, modules_restored: None
) -> None:
    await make_admin(client)
    domain = await _domain(client)
    body = {"trusted_domain_id": str(domain), "checks": FIVE, "exclude": ["/admin", "/api"]}
    url = f"{ADMIN}/active/owner-scan"

    # shipped state: everything locked; readiness says so
    ready = (await client.get(url)).json()
    assert {"approval", "modules", "scanner_switch"} <= set(ready["blocked_by"])
    r = await client.post(url, json=body)
    assert r.status_code == 422 and _code(r) == "active_testing_not_approved"

    monkeypatch.setattr(get_settings(), "active_testing_approved", True)  # 1. founder approval
    r = await client.post(url, json=body)
    assert r.status_code == 422 and _code(r) == "active_module_off"

    await _set_modules(FIVE, on=True)  # 2. modules
    r = await client.post(f"{ADMIN}/active/kill", json={"engaged": True})
    assert r.status_code == 200
    r = await client.post(url, json=body)
    assert r.status_code == 422 and _code(r) == "active_killed"  # 3. kill switch
    r = await client.post(f"{ADMIN}/active/kill", json={"engaged": False})
    assert r.status_code == 200

    r = await client.post(url, json=body)
    assert r.status_code == 422 and _code(r) == "scanner_active_disabled"  # 4. scanner switch
    await _scanner_on(redis)

    r = await client.post(url, json={**body, "checks": [*FIVE, "active_ssrf"]})
    assert r.status_code == 422 and _code(r) == "active_module_off"  # ssrf is off
    await _set_modules(["active_ssrf"], on=True)
    r = await client.post(url, json={**body, "checks": ["active_ssrf"]})
    assert r.status_code == 422 and _code(r) == "oob_not_configured"

    pending = await _domain(client, status="suspended")  # 5. only an active trusted domain
    r = await client.post(url, json={**body, "trusted_domain_id": str(pending)})
    assert r.status_code == 404
    r = await client.post(url, json={**body, "trusted_domain_id": str(uuid.uuid4())})
    assert r.status_code == 404
    assert await _active_jobs(redis) == []  # nothing was queued by any refusal

    assert (await client.get(url)).json()["blocked_by"] == []
    r = await client.post(url, json=body)
    assert r.status_code == 202, r.text
    started = r.json()
    scan_id = uuid.UUID(started["scan_id"])
    assert started["checks"] == sorted(FIVE) and started["exclude"] == ["/admin", "/api"]

    jobs = await _active_jobs(redis)
    assert len(jobs) == 1
    job = jobs[0]
    assert job["scan_id"] == str(scan_id) and job["token"] == "ghv_owner-test-token"
    assert job["target"] == started["origin"] and job["checks"] == sorted(FIVE)
    assert job["consent_id"] == started["consent_id"] and job["session_key"] == ""

    async with db_session(DbContext.system()) as session:
        consent = await session.get(ActiveConsent, uuid.UUID(started["consent_id"]))
        scan = await session.get(Scan, scan_id)
        audit = (await session.execute(select(AuditLog).where(AuditLog.target == str(scan_id)))).scalar_one()
    assert consent is not None and consent.consent_version == owner_scan.OWNER_CONSENT_VERSION
    assert consent.consent_sha256 == owner_scan.OWNER_STATEMENT_SHA256 and consent.origin == started["origin"]
    assert scan is not None and scan.status == "queued" and scan.checks == sorted(FIVE)
    assert audit.action == "active.scan.started" and audit.metadata_["origin"] == started["origin"]

    # 6. one active scan per origin, until that scan ends
    r = await client.post(url, json=body)
    assert r.status_code == 409 and _code(r) == "active_scan_running"
    ended = {"v": 1, "type": "scan.failed", "scan_id": str(scan_id), "error": "active_killed"}
    await handle_event(redis, {**ended, "at": datetime.now(UTC).isoformat()})
    r = await client.post(url, json=body)
    assert r.status_code == 202, r.text


async def test_idor_accounts_go_only_to_a_one_time_key(
    client: httpx.AsyncClient, redis: Redis, monkeypatch: pytest.MonkeyPatch, modules_restored: None
) -> None:
    await make_admin(client)
    domain = await _domain(client)
    monkeypatch.setattr(get_settings(), "active_testing_approved", True)
    await _set_modules(["active_idor"], on=True)
    await _scanner_on(redis)
    url = f"{ADMIN}/active/owner-scan"
    a = {"cookie": "sid=secret-a", "marker": "alice-test@own.example"}
    body = {"trusted_domain_id": str(domain), "checks": ["active_idor"], "account_a": a}
    r = await client.post(url, json=body)
    assert r.status_code == 422 and _code(r) == "idor_needs_two_accounts"
    b = {"cookie": "sid=secret-b", "marker": "bob-test@own.example"}
    r = await client.post(url, json={**body, "account_b": b})
    assert r.status_code == 202, r.text
    assert "secret" not in r.text
    job = (await _active_jobs(redis))[0]
    assert "secret" not in json.dumps(job)  # cookies never travel in the job stream
    key = str(job["session_key"])
    assert key.startswith(owner_scan.SESSIONS_PREFIX) and key.endswith(str(job["job_id"]))
    assert 0 < await redis.ttl(key) <= owner_scan.SESSIONS_TTL_SECONDS
    stored = json.loads(await redis.get(key))
    assert stored["a"]["cookie"] == "sid=secret-a" and stored["b"]["name"] == "B"
    async with db_session(DbContext.system()) as session:
        audit = (
            await session.execute(select(AuditLog).where(AuditLog.target == str(job["scan_id"])))
        ).scalar_one()
    assert "secret" not in json.dumps(audit.metadata_)


async def test_owner_scan_is_admin_only(client: httpx.AsyncClient, redis: Redis) -> None:
    from .conftest import signed_in

    await signed_in(client)
    assert (await client.get(f"{ADMIN}/active/owner-scan")).status_code == 404
    r = await client.post(f"{ADMIN}/active/owner-scan", json={"trusted_domain_id": str(uuid.uuid4()),
                                                              "checks": ["active_xss"]})  # fmt: skip
    assert r.status_code == 404
    assert await _active_jobs(redis) == []
