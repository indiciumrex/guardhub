"""Super-admin observe-only scans (profile prompt item 3) against real PostgreSQL + Redis.

The boundary under test: without an ownership proof only observe-only checks can ever be queued,
only by a listed super-admin, only while the server switch is on, and never without the recorded
authorisation statement. Anything beyond observation needs a verified site, with no exception.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import select

from guardhub_api.admin.observe import STATEMENT_SHA256, STATEMENT_VERSION
from guardhub_api.config import get_settings
from guardhub_api.db.models import AuditLog, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.contract_gen import OBSERVE_CHECK_IDS
from guardhub_api.scans.queue import JOBS_STREAM

from .conftest import new_client, signed_in
from .test_trusted_domains import make_admin

OBSERVE = "/api/v1/admin/observe-scans"
TARGET = "https://observe-target.example.com"


@pytest.fixture(autouse=True)
async def _fresh_rate_limits(redis: Redis) -> AsyncIterator[None]:
    yield


def _body(**over: object) -> dict[str, object]:
    body: dict[str, object] = {
        "target_url": TARGET,
        "relationship": "client",
        "note": "The site owner asked us by e-mail on 2026-11-26 to check it.",
        "statement_version": STATEMENT_VERSION,
        "accept_statement": True,
    }
    body.update(over)
    return body


async def _me(client: httpx.AsyncClient) -> uuid.UUID:
    return uuid.UUID((await client.get("/api/v1/auth/me")).json()["id"])


async def _queued_kinds(redis: Redis) -> list[tuple[str, list[str]]]:
    out = []
    for _id, fields in await redis.xrange(JOBS_STREAM):
        job = json.loads(fields["payload"])
        if job["kind"] != "verify":
            out.append((job["kind"], list(job.get("checks") or [])))
    return out


async def test_only_listed_super_admins_see_it(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_admin(client)
    monkeypatch.setattr(get_settings(), "observe_scan_enabled", True)
    monkeypatch.setattr(get_settings(), "super_admin_ids", "")
    assert (await client.get(OBSERVE)).status_code == 404  # an admin, but not a super-admin
    assert (await client.post(OBSERVE, json=_body())).status_code == 404
    async with new_client("198.51.100.97") as customer:
        await signed_in(customer)
        monkeypatch.setattr(get_settings(), "super_admin_ids", str(await _me(customer)))
        assert (await customer.get(OBSERVE)).status_code == 404  # listed, but not an admin


async def test_switch_statement_and_boundary(
    client: httpx.AsyncClient, redis: Redis, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_admin(client)
    me = await _me(client)
    monkeypatch.setattr(get_settings(), "super_admin_ids", f"not-a-uuid, {me}")

    # Off by default: nothing is queued.
    monkeypatch.setattr(get_settings(), "observe_scan_enabled", False)
    ready = (await client.get(OBSERVE)).json()
    assert ready["enabled"] is False and ready["statement_sha256"] == STATEMENT_SHA256
    assert set(ready["checks"]) <= set(OBSERVE_CHECK_IDS)
    for needs_proof in ("exposed_env", "open_admin", "default_creds", "dns_email", "active_sqli"):
        assert needs_proof in ready["needs_verified_site"]
    r = await client.post(OBSERVE, json=_body())
    assert r.status_code == 422 and r.json()["error"]["code"] == "observe_scan_off"

    monkeypatch.setattr(get_settings(), "observe_scan_enabled", True)
    # The statement is mandatory, in its current version.
    r = await client.post(OBSERVE, json=_body(accept_statement=False))
    assert r.json()["error"]["code"] == "statement_required"
    r = await client.post(OBSERVE, json=_body(statement_version="old"))
    assert r.json()["error"]["code"] == "statement_required"
    assert (await client.post(OBSERVE, json=_body(note="short"))).status_code == 422
    # The boundary: probing, credentials, zone transfer, active tests need a verified site.
    for forbidden in ("exposed_env", "default_creds", "dns_email", "active_xss", "js_secrets"):
        r = await client.post(OBSERVE, json=_body(checks=["tls_cert", forbidden]))
        assert r.status_code == 422 and r.json()["error"]["code"] == "ownership_required", forbidden
    assert await _queued_kinds(redis) == []

    # Allowed: an observe_scan job with observe-only checks, on record before it was queued.
    r = await client.post(OBSERVE, json=_body())
    assert r.status_code == 202, r.text
    scan_id = r.json()["id"]
    kinds = await _queued_kinds(redis)
    assert len(kinds) == 1 and kinds[0][0] == "observe_scan"
    assert kinds[0][1] and set(kinds[0][1]) <= set(OBSERVE_CHECK_IDS)
    async with db_session(DbContext.system()) as session:
        scan = await session.get(Scan, uuid.UUID(scan_id))
        assert scan is not None and scan.trigger == "observe" and scan.project_id is None
        rows = (
            (
                await session.execute(
                    select(AuditLog).where(AuditLog.actor == f"admin:{me}").order_by(AuditLog.id)
                )
            )
            .scalars()
            .all()
        )
    declared = [a for a in rows if a.action == "admin.observe_scan.declared"]
    assert declared and declared[-1].target == TARGET
    meta = declared[-1].metadata_
    assert meta["relationship"] == "client" and meta["statement_sha256"] == STATEMENT_SHA256
    assert "asked us" in meta["note"]
    assert [a.action for a in rows][-2:] == ["admin.observe_scan.declared", "admin.observe_scan.queued"]
    # The admin opens the report like any of their own scans.
    assert (await client.get(f"/api/v1/scans/{scan_id}")).status_code == 200


async def test_private_targets_stay_refused(
    client: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    await make_admin(client)
    monkeypatch.setattr(get_settings(), "super_admin_ids", str(await _me(client)))
    monkeypatch.setattr(get_settings(), "observe_scan_enabled", True)
    for target in ("http://127.0.0.1", "http://10.0.0.5", "http://localhost:8080"):
        r = await client.post(OBSERVE, json=_body(target_url=target))
        assert r.status_code == 422, target
