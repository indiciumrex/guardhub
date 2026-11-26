"""Verified sites (profile prompt, item 2) against real PostgreSQL + Redis: an admin sees every
site they proved in one list; a lapsed trusted domain shows as failed (and its project as not
verified), never as verified; one click re-proves it; nobody else sees the page."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import update

from guardhub_api.db.models import AdminTrustedDomain
from guardhub_api.db.session import DbContext, db_session

from .conftest import FakeScanner, new_client, signed_in
from .test_trusted_domains import add_active_domain, make_admin, unique_host

SITES = "/api/v1/admin/sites"


@pytest.fixture(autouse=True)
async def _fresh_rate_limits(redis: Redis) -> AsyncIterator[None]:
    yield


async def test_sites_lists_lapses_and_reverifies(client: httpx.AsyncClient, scanner: FakeScanner) -> None:
    await make_admin(client)
    host = unique_host("sites")
    domain = await add_active_domain(client, scanner, f"https://{host}")
    r = await client.post("/api/v1/projects", json={"name": "Mine", "target_url": f"https://{host}"})
    assert r.status_code == 201 and r.json()["verified"] is True
    project_id = r.json()["id"]

    rows = (await client.get(SITES)).json()
    row = next(x for x in rows if x["host"] == host)
    assert row["status"] == "verified" and row["source"] == "trusted_domain"
    assert row["project_ids"] == [project_id]
    assert not [x for x in rows if x["source"] == "project" and x["id"] == project_id]  # not twice

    # The domain's proof lapses (the daily re-check suspended it).
    async with db_session(DbContext.system()) as session:
        await session.execute(
            update(AdminTrustedDomain)
            .where(AdminTrustedDomain.id == domain["id"])
            .values(status="suspended", last_check_error="timeout")
        )
    row = next(x for x in (await client.get(SITES)).json() if x["host"] == host)
    assert row["status"] == "failed" and row["last_error"] == "timeout"
    assert (await client.get(f"/api/v1/projects/{project_id}")).json()["verified"] is False
    listed = next(p for p in (await client.get("/api/v1/projects")).json() if p["id"] == project_id)
    assert listed["verified"] is False

    # One click re-proves it (through the scanner, exactly like the domain's own verify).
    scanner.verify_ok = True
    r = await client.post(f"{SITES}/trusted_domain/{domain['id']}/reverify")
    assert r.status_code == 200, r.text
    row = next(x for x in r.json() if x["host"] == host)
    assert row["status"] == "verified"
    assert (await client.get(f"/api/v1/projects/{project_id}")).json()["verified"] is True

    # A failed proof keeps it failed and says why.
    scanner.verify_ok = False
    r = await client.post(f"{SITES}/project/{project_id}/reverify")
    assert r.status_code == 422


async def test_sites_is_admin_only() -> None:
    async with new_client("198.51.100.95") as customer:
        await signed_in(customer)
        assert (await customer.get(SITES)).status_code == 404
    async with new_client("198.51.100.96") as anonymous:
        assert (await anonymous.get(SITES)).status_code == 404
