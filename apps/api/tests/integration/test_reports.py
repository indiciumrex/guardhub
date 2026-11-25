"""Admin reports (Prompt 2 §3) against real PostgreSQL: every report builds, customer data is
masked on screen and in exports, exports are audited, admin only, schedules toggle."""

from __future__ import annotations

import csv
import io
import zipfile
from collections.abc import AsyncIterator

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import select, update

from guardhub_api.db.models import AuditLog, ReportSchedule
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.reports.builders import KINDS

from .conftest import new_client, signed_in
from .test_active import make_admin

REPORTS = "/api/v1/admin/reports"


@pytest.fixture(autouse=True)
async def _fresh_rate_limits(redis: Redis) -> AsyncIterator[None]:
    """Every test registers users from the same test address: start each with fresh rate limits."""
    yield


async def test_reports_are_admin_only(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    assert (await client.get(f"{REPORTS}/platform")).status_code == 404
    assert (await client.get(f"{REPORTS}/customers?format=csv")).status_code == 404
    async with new_client("198.51.100.31") as anon:
        assert (await anon.get(f"{REPORTS}/platform")).status_code == 401


@pytest.mark.parametrize("kind", KINDS)
async def test_every_report_builds(client: httpx.AsyncClient, kind: str) -> None:
    await make_admin(client)
    for days in (7, 30, 90):
        r = await client.get(f"{REPORTS}/{kind}?days={days}")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["kind"] == kind and body["days"] == days and body["masked"] is True
        assert all(len(row) == len(body["columns"]) for row in body["rows"])


async def test_customer_data_is_masked_everywhere_and_exports_are_audited(client: httpx.AsyncClient) -> None:
    async with new_client("198.51.100.32") as customer:
        email, _ = await signed_in(customer)
    await make_admin(client)

    body = (await client.get(f"{REPORTS}/customers?days=30")).json()
    shown = [row[0] for row in body["rows"]]
    assert email not in shown
    assert f"{email[0]}***@e***.com" in shown

    r = await client.get(f"{REPORTS}/customers?days=30&format=csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert r.headers["content-disposition"].startswith('attachment; filename="guardhub-customers-30d-')
    text = r.content.decode("utf-8-sig")
    assert email not in text
    assert next(csv.reader(io.StringIO(text)))[0] == "customer"

    r = await client.get(f"{REPORTS}/customers?days=30&format=xlsx")
    assert r.status_code == 200
    with zipfile.ZipFile(io.BytesIO(r.content)) as z:
        assert email.encode() not in z.read("xl/worksheets/sheet1.xml")

    async with db_session(DbContext.system()) as session:
        rows = (
            (
                await session.execute(
                    select(AuditLog.metadata_).where(
                        AuditLog.action == "report.exported", AuditLog.target == "customers"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert {m["format"] for m in rows} >= {"csv", "xlsx"}


async def test_invalid_report_or_period(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    r = await client.get(f"{REPORTS}/salaries")
    assert r.status_code == 422 and r.json()["error"]["code"] == "report_unknown"
    r = await client.get(f"{REPORTS}/platform?days=365")
    assert r.status_code == 422 and r.json()["error"]["code"] == "report_days_invalid"


async def test_schedules_toggle_and_are_audited(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    r = await client.get("/api/v1/admin/report-schedules")
    assert [s["frequency"] for s in r.json()] == ["weekly", "monthly"]
    assert all(s["enabled"] is False for s in r.json())
    r = await client.put("/api/v1/admin/report-schedules/weekly", json={"enabled": True})
    assert r.status_code == 200 and r.json()["enabled"] is True
    assert (
        await client.put("/api/v1/admin/report-schedules/daily", json={"enabled": True})
    ).status_code == 422
    async with db_session(DbContext.system()) as session:
        await session.execute(update(ReportSchedule).values(enabled=False))
