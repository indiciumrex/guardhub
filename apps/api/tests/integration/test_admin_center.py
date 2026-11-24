"""Admin control centre (§8.3) against real PostgreSQL (RLS) + Redis.

Rules under test: every endpoint is admin-only (404 otherwise); cancelling stops a scan for good
(cancel + kill keys, later scanner events ignored) and is audited; findings are grouped by
fingerprint with standard ids, and triage is audited and feeds the module's production
false-positive count; the score is explained by the same formula that computed it; maintenance
keeps a module out of new scans; the active-testing state is reported off unless every switch
allows it; audit rows carry a keyed IP hash, never an IP.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import httpx
from redis.asyncio import Redis

from guardhub_api.admin.bootstrap import _set_role
from guardhub_api.db.models import Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.modules.registry import enabled_check_ids
from guardhub_api.scans.ingest import handle_event
from guardhub_api.worker import consume_once, ensure_group

from .conftest import FakeScanner, new_client, raw_finding, signed_in

ADMIN = "/api/v1/admin"


async def ingest(redis: Redis) -> None:
    await ensure_group(redis)
    for _ in range(5):
        await consume_once(redis, "test-worker", block_ms=50)


async def customer_scan(owner: httpx.AsyncClient, redis: Redis, scanner: FakeScanner) -> str:
    """A regular customer with one verified project and one completed scan; returns the scan id."""
    await signed_in(owner)
    host = f"center-{uuid.uuid4().hex[:8]}.example"
    r = await owner.post("/api/v1/projects", json={"name": "Center", "target_url": host})
    assert r.status_code == 201, r.text
    project_id = r.json()["id"]
    assert (await owner.post(f"/api/v1/projects/{project_id}/verify")).json()["verified"] is True
    scanner.findings = [
        raw_finding(
            "exposed_env", "env_file_exposed", f"https://{host}/.env", {"path": "/.env", "secret_count": "2"}
        ),
        raw_finding("security_headers", "csp_missing", f"https://{host}/"),
    ]
    r = await owner.post(f"/api/v1/projects/{project_id}/scans")
    assert r.status_code == 202, r.text
    scan_id = str(r.json()["id"])
    await ingest(redis)
    assert (await owner.get(f"/api/v1/scans/{scan_id}")).json()["status"] == "done"
    return scan_id


async def make_admin(client: httpx.AsyncClient) -> str:
    email, _ = await signed_in(client)
    assert await _set_role(email, "admin") == 0
    return email


async def test_center_endpoints_are_admin_only(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    some = uuid.uuid4()
    for method, path, body in (
        ("GET", "/overview", None),
        ("GET", "/orchestration", None),
        ("GET", "/monitoring", None),
        ("GET", "/findings", None),
        ("GET", "/modules/stats", None),
        ("GET", "/scans/detailed", None),
        ("GET", f"/scans/{some}/risk", None),
        ("POST", f"/scans/{some}/cancel", None),
        ("POST", f"/scans/{some}/rerun", None),
        ("PUT", "/findings/abc/triage", {"status": "verified"}),
        ("PATCH", "/modules/tls_cert/config", {"maintenance": True}),
        ("GET", "/modules/tls_cert/changelog", None),
    ):
        r = await client.request(method, ADMIN + path, json=body)
        assert r.status_code == 404, (method, path, r.status_code)


async def test_overview_findings_triage_risk_and_rerun(redis: Redis, scanner: FakeScanner) -> None:
    async with new_client("198.51.100.8") as owner, new_client() as client:
        scan_id = await customer_scan(owner, redis, scanner)  # another user's project and scan
        await make_admin(client)

        ov = (await client.get(f"{ADMIN}/overview")).json()
        assert ov["scans"]["completed"] >= 1 and ov["scans"]["total"] >= 1
        assert ov["findings"]["total"] >= 2
        assert ov["sentry"]["configured"] is False
        assert ov["queue"]["available"] is True
        assert ov["recent_audit"], "recent admin/user actions are listed"
        # audit rows written during a request carry a keyed IP hash, never the IP itself
        assert any(a["ip_hash"] for a in ov["recent_audit"])
        assert all("198.51.100.7" not in json.dumps(a) for a in ov["recent_audit"])

        groups = (await client.get(f"{ADMIN}/findings", params={"check_id": "exposed_env"})).json()
        env = next(g for g in groups if g["finding_key"] == "env_file_exposed")
        assert env["triage"] == "new" and env["occurrences"] >= 1
        assert "CWE-538" in env["classification"]["cwe"]
        assert env["classification"]["cvss_vector"].startswith("CVSS:3.1/")
        assert env["title"]  # rendered from the curated catalog

        r = await client.put(
            f"{ADMIN}/findings/{env['fingerprint']}/triage", json={"status": "false_positive", "note": "lab"}
        )
        assert r.status_code == 200 and r.json()["status"] == "false_positive"
        assert (
            await client.put(f"{ADMIN}/findings/{env['fingerprint']}/triage", json={"status": "bogus"})
        ).status_code == 422
        fp = (await client.get(f"{ADMIN}/findings", params={"triage": "false_positive"})).json()
        assert any(g["fingerprint"] == env["fingerprint"] for g in fp)
        stats = {s["check_id"]: s for s in (await client.get(f"{ADMIN}/modules/stats")).json()}
        assert stats["exposed_env"]["triage"]["false_positive"] >= 1
        trail = (
            await client.get(f"{ADMIN}/audit", params={"action": "finding.", "target": env["fingerprint"]})
        ).json()
        assert trail[0]["changes"]["from"] == "new" and trail[0]["changes"]["to"] == "false_positive"

        risk = (await client.get(f"{ADMIN}/scans/{scan_id}/risk", params={"locale": "tr"})).json()
        assert risk["recomputed"] == risk["score"]
        assert sum(c["count"] for c in risk["contributions"]) == len(risk["findings"]) == 2

        rows = (await client.get(f"{ADMIN}/scans/detailed", params={"stage": "completed"})).json()
        row = next(s for s in rows if s["id"] == scan_id)
        assert row["lifecycle"] == "completed" and row["can_rerun"] is True and row["can_cancel"] is False
        assert row["ownership"]["kind"] == "project" and row["ownership"]["verified_at"]

        r = await client.post(f"{ADMIN}/scans/{scan_id}/rerun")
        assert r.status_code == 200, r.text
        new_id = r.json()["id"]
        assert new_id != scan_id and r.json()["lifecycle"] in ("queued", "running", "completed")
        assert r.json()["owner_email"] and r.json()["project_name"] == "Center"  # still the customer's scan
        assert (await client.get(f"{ADMIN}/audit", params={"action": "scan.rerun", "target": new_id})).json()
        await ingest(redis)


async def test_cancel_stops_a_scan_for_good(client: httpx.AsyncClient, redis: Redis) -> None:
    email, _ = await signed_in(client)
    assert await _set_role(email, "admin") == 0
    async with db_session(DbContext.system()) as session:
        scan = Scan(target_url="https://cancel.example", status="running", public_token_hash=uuid.uuid4().hex)
        session.add(scan)
        await session.flush()
        scan_id = scan.id

    r = await client.post(f"{ADMIN}/scans/{scan_id}/cancel")
    assert r.status_code == 200, r.text
    assert r.json()["lifecycle"] == "cancelled" and r.json()["can_cancel"] is False
    assert await redis.exists(f"gh:scan:cancel:{scan_id}") == 1
    assert await redis.exists(f"gh:active:kill:{scan_id}") == 1

    # the scanner's later completion never reopens it
    await handle_event(
        redis,
        {
            "v": 1,
            "type": "scan.completed",
            "scan_id": str(scan_id),
            "at": datetime.now(UTC).isoformat(),
            "findings": [],
            "check_results": [],
        },
    )
    rows = (await client.get(f"{ADMIN}/scans/detailed", params={"stage": "cancelled"})).json()
    assert any(s["id"] == str(scan_id) for s in rows)
    assert (await client.post(f"{ADMIN}/scans/{scan_id}/cancel")).status_code == 409
    trail = (
        await client.get(f"{ADMIN}/audit", params={"action": "scan.cancel", "target": str(scan_id)})
    ).json()
    assert trail and trail[0]["changes"]["from"] == "running" and trail[0]["actor_email"] == email.lower()


async def test_module_centre_maintenance_gate_and_changelog(client: httpx.AsyncClient) -> None:
    email, _ = await signed_in(client)
    assert await _set_role(email, "admin") == 0
    modules = {m["key"]: m for m in (await client.get(f"{ADMIN}/modules")).json()}
    xss = modules["active_xss"]
    assert xss["stage"] == "beta" and xss["status"] == "disabled"
    assert xss["enable_blocked"] == "active_testing_not_approved"
    assert xss["gate"]["gate"] == "M" and xss["gate"]["measured"] is True
    assert modules["tls_cert"]["gate"]["gate"] == "L" and modules["tls_cert"]["stage"] == "ga"

    r = await client.patch(f"{ADMIN}/modules/info_leak/config", json={"maintenance": True})
    assert r.status_code == 200 and r.json()["status"] == "maintenance"
    try:
        async with db_session(DbContext.system()) as session:
            assert "info_leak" not in await enabled_check_ids(session)
        assert (
            await client.patch(f"{ADMIN}/modules/info_leak/config", json={"min_plan": "gold"})
        ).status_code == 422
        log = (await client.get(f"{ADMIN}/modules/info_leak/changelog")).json()
        assert log[0]["action"] == "module.config" and log[0]["changes"]["maintenance_to"] == "true"
    finally:
        r = await client.patch(f"{ADMIN}/modules/info_leak/config", json={"maintenance": False})
        assert r.json()["status"] == "active"


async def test_orchestration_reports_active_testing_off(client: httpx.AsyncClient, redis: Redis) -> None:
    email, _ = await signed_in(client)
    assert await _set_role(email, "admin") == 0
    await redis.set(
        "gh:scanner:info:t1",
        json.dumps(
            {
                "consumer": "t1",
                "host_rps": 2,
                "host_burst": 2,
                "max_requests_per_scan": 220,
                "request_timeout_ms": 10000,
                "workers": 4,
                "check_concurrency": 3,
                "active_enabled": False,
            }
        ),
        ex=60,
    )
    o = (await client.get(f"{ADMIN}/orchestration")).json()
    assert o["active"] == {
        "approved": False,
        "scanner_switch": "off",
        "global_kill": False,
        "modules_on": [],
        "oob_configured": False,
        "effective": "off",
    }
    assert o["passive_limits"]["requests_per_second_per_host"] == 2
    assert o["active_limits"]["requests_per_scan"] == 300 and o["active_limits"]["requests_per_second"] == 1

    await redis.set("gh:active:kill", "1")
    assert (await client.get(f"{ADMIN}/orchestration")).json()["active"]["global_kill"] is True

    m = (await client.get(f"{ADMIN}/monitoring")).json()
    assert m["health"]["components"]["database"] == "ok"
    assert m["scanners"][0]["consumer"] == "t1" and m["sentry"]["configured"] is False
