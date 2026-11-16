"""Admin trusted domains (ADR-0003, docs/architecture.md §8.5) against real PostgreSQL (RLS) + Redis.

The rule under test: no path scans a target without a currently valid proof. A trusted domain
only moves WHEN the admin is asked for that proof (once), never WHETHER it exists.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
from redis.asyncio import Redis
from sqlalchemy import select, text, update

from guardhub_api.admin.bootstrap import _set_role
from guardhub_api.admin.trusted_domains.jobs import recheck_trusted_domains
from guardhub_api.db.models import AdminTrustedDomain, AuditLog, Project
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.scans.queue import JOBS_STREAM

from .conftest import FakeScanner, new_client, signed_in

TD = "/api/v1/admin/trusted-domains"
PASSWORD = "a-Strong-passphrase-42"


def unique_host(label: str) -> str:
    return f"{label}-{uuid.uuid4().hex[:8]}.example.com"


async def make_admin(client: httpx.AsyncClient) -> str:
    """Register with 2FA, then promote to admin (the operator CLI path). Returns the email."""
    email, _ = await signed_in(client)
    assert await _set_role(email, "admin") == 0
    return email


async def queued_scan_targets(redis: Redis) -> list[str]:
    """Targets of every scan job currently on gh:jobs (verify jobs excluded)."""
    targets = []
    for _id, fields in await redis.xrange(JOBS_STREAM):
        job = json.loads(fields["payload"])
        if job["kind"] == "scan":
            targets.append(job["target"])
    return targets


async def add_domain(client: httpx.AsyncClient, target: str) -> dict[str, object]:
    r = await client.post(TD, json={"target_url": target})
    assert r.status_code == 201, r.text
    body: dict[str, object] = r.json()
    return body


async def add_active_domain(
    client: httpx.AsyncClient, scanner: FakeScanner, target: str
) -> dict[str, object]:
    domain = await add_domain(client, target)
    scanner.verify_ok = True
    r = await client.post(f"{TD}/{domain['id']}/verify")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "active"
    body: dict[str, object] = r.json()
    return body


async def audit_actions(target: str) -> list[str]:
    async with db_session(DbContext.system()) as session:
        rows = (
            (await session.execute(select(AuditLog).where(AuditLog.target == target).order_by(AuditLog.id)))
            .scalars()
            .all()
        )
    return [r.action for r in rows]


async def domain_status(domain_id: object) -> str:
    async with db_session(DbContext.system()) as session:
        row = await session.get(AdminTrustedDomain, uuid.UUID(str(domain_id)))
        assert row is not None
        return row.status


async def test_every_route_is_404_without_a_full_admin_session(redis: Redis, scanner: FakeScanner) -> None:
    some_id = uuid.uuid4()
    calls = [
        ("GET", TD, None),
        ("POST", TD, {"target_url": "example.com"}),
        ("POST", TD, {"not": "valid"}),  # even a malformed body must not reveal the route
        ("POST", f"{TD}/{some_id}/verify", None),
        ("POST", f"{TD}/{some_id}/scan", None),
        ("DELETE", f"{TD}/{some_id}", None),
    ]

    async def assert_hidden(client: httpx.AsyncClient) -> None:
        for method, url, body in calls:
            r = await client.request(method, url, json=body)
            assert r.status_code == 404, (method, url, r.status_code, r.text)
            assert r.json()["error"]["code"] == "not_found"

    async with new_client("198.51.100.200") as anonymous:
        await assert_hidden(anonymous)
    async with new_client("198.51.100.201") as user:
        await signed_in(user)
        await assert_hidden(user)
    async with new_client("198.51.100.202") as admin:
        email = await make_admin(admin)
        assert (await admin.get(TD)).status_code == 200
        # a fresh login without the TOTP step is a pre-MFA session: still hidden
        assert (await admin.post("/api/v1/auth/logout")).status_code == 204
        r = await admin.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert r.json() == {"mfa": "required"}
        await assert_hidden(admin)
    assert await queued_scan_targets(redis) == []


async def test_pending_domain_flow_verify_failure_then_scan(redis: Redis, scanner: FakeScanner) -> None:
    host = unique_host("flow")
    async with new_client("198.51.100.203") as admin:
        await make_admin(admin)
        domain = await add_domain(admin, f"HTTPS://{host.upper()}/some/path?q=1")
        assert domain["status"] == "pending"
        assert domain["host"] == host and domain["target_origin"] == f"https://{host}"
        verification = domain["verification"]
        assert isinstance(verification, dict)
        assert verification["well_known_url"] == f"https://{host}/.well-known/guardhub-verify.txt"
        assert verification["dns_name"] == f"_guardhub.{host}"
        assert str(verification["token"]).startswith("ghv_")
        did = domain["id"]

        # pending can't scan, and nothing reaches the scanner
        r = await admin.post(f"{TD}/{did}/scan")
        assert r.status_code == 422 and r.json()["error"]["code"] == "trusted_domain_inactive"
        # a pending domain doesn't make projects verified either
        p = (await admin.post("/api/v1/projects", json={"name": "P", "target_url": host})).json()
        assert p["verified"] is False
        assert (await admin.post(f"/api/v1/projects/{p['id']}/scans")).json()["error"]["code"] == (
            "ownership_not_verified"
        )
        assert (await admin.delete(f"/api/v1/projects/{p['id']}")).status_code == 204

        # verification failure keeps it pending
        scanner.verify_ok = False
        r = await admin.post(f"{TD}/{did}/verify")
        assert r.status_code == 422 and r.json()["error"]["code"] == "ownership_not_verified"
        assert r.json()["error"]["details"]["reason"] == "not_found"
        assert await domain_status(did) == "pending"
        assert await queued_scan_targets(redis) == []

        # proof found → active; scan creates the project (verified via the domain) and queues it
        scanner.verify_ok = True
        r = await admin.post(f"{TD}/{did}/verify")
        assert r.status_code == 200, r.text
        active = r.json()
        assert active["status"] == "active" and active["method"] == "well_known"
        assert active["verified_at"] is not None and active["last_checked_at"] is not None

        r = await admin.post(f"{TD}/{did}/scan")
        assert r.status_code == 202, r.text
        scan = r.json()
        assert scan["status"] == "queued" and scan["target_url"] == f"https://{host}"
        assert await queued_scan_targets(redis) == [f"https://{host}"]

        project = (await admin.get(f"/api/v1/projects/{scan['project_id']}")).json()
        assert project["verified"] is True and project["target_url"] == f"https://{host}"
        async with db_session(DbContext.system()) as session:
            row = await session.get(Project, uuid.UUID(scan["project_id"]))
            assert row is not None and row.ownership_method == "trusted_domain"

        # a second scan while the first is still queued is refused; the project is reused
        r = await admin.post(f"{TD}/{did}/scan")
        assert r.status_code == 409 and r.json()["error"]["code"] == "scan_in_progress"

        listed = (await admin.get(TD)).json()
        assert [d["id"] for d in listed if d["host"] == host] == [did]

        # the same host can't be added twice while live (any scheme: one entry per host)
        r = await admin.post(TD, json={"target_url": f"http://{host}"})
        assert r.status_code == 409 and r.json()["error"]["code"] == "trusted_domain_exists"

    assert await audit_actions(str(did)) == [
        "admin.trusted_domain.added",
        "admin.trusted_domain.verified",
        "admin.trusted_domain.scan",
    ]


async def test_active_domain_covers_exactly_one_origin(redis: Redis, scanner: FakeScanner) -> None:
    host = unique_host("exact")
    async with new_client("198.51.100.204") as admin:
        await make_admin(admin)
        await add_active_domain(admin, scanner, host)

        async def create(target: str) -> dict[str, object]:
            r = await admin.post("/api/v1/projects", json={"name": "X", "target_url": target})
            assert r.status_code == 201, r.text
            body: dict[str, object] = r.json()
            return body

        exact = await create(f"https://{host}/any/path")
        assert exact["verified"] is True
        r = await admin.post(f"/api/v1/projects/{exact['id']}/scans")
        assert r.status_code == 202, r.text

        # subdomain, other port, other scheme, never-trusted host: normal proof flow
        for target in (f"sub.{host}", f"https://{host}:8443", f"http://{host}", unique_host("never")):
            other = await create(target)
            assert other["verified"] is False, target
            r = await admin.post(f"/api/v1/projects/{other['id']}/scans")
            assert r.status_code == 422 and r.json()["error"]["code"] == "ownership_not_verified", target

    assert await queued_scan_targets(redis) == [f"https://{host}"]
    async with db_session(DbContext.system()) as session:
        n = (
            await session.execute(
                text(
                    "SELECT count(*) FROM audit_logs WHERE action = 'project.create' "
                    "AND target = :t AND metadata->>'ownership_method' = 'trusted_domain'"
                ),
                {"t": str(exact["id"])},
            )
        ).scalar_one()
    assert n == 1


async def test_admins_cannot_see_or_use_each_others_domains(redis: Redis, scanner: FakeScanner) -> None:
    host = unique_host("iso")
    async with new_client("198.51.100.205") as admin_a, new_client("198.51.100.206") as admin_b:
        await make_admin(admin_a)
        await make_admin(admin_b)
        domain = await add_active_domain(admin_a, scanner, host)
        did = domain["id"]

        assert all(d["id"] != did for d in (await admin_b.get(TD)).json())
        for method, url in (
            ("POST", f"{TD}/{did}/verify"),
            ("POST", f"{TD}/{did}/scan"),
            ("DELETE", f"{TD}/{did}"),
        ):
            r = await admin_b.request(method, url)
            assert r.status_code == 404 and r.json()["error"]["code"] == "trusted_domain_not_found"

        # B's project for A's host is NOT verified by A's domain
        p = (await admin_b.post("/api/v1/projects", json={"name": "B", "target_url": host})).json()
        assert p["verified"] is False
        # B can add the same host independently; it starts pending
        assert (await add_domain(admin_b, host))["status"] == "pending"
        me_b = (await admin_b.get("/api/v1/auth/me")).json()

    assert await domain_status(did) == "active"  # B's DELETE did nothing
    assert await queued_scan_targets(redis) == []

    # RLS itself: another admin's context and a plain user's context see none of A's rows
    for ctx in (
        DbContext(role="admin", user_id=uuid.UUID(me_b["id"])),
        DbContext.for_user(uuid.uuid4(), "user"),
    ):
        async with db_session(ctx) as session:
            rows = (
                (await session.execute(select(AdminTrustedDomain).where(AdminTrustedDomain.host == host)))
                .scalars()
                .all()
            )
            assert all(str(r.id) != did for r in rows)
            if ctx.role == "user":
                assert rows == []


async def test_recheck_suspends_blocks_rescans_and_reactivates(redis: Redis, scanner: FakeScanner) -> None:
    host = unique_host("recheck")
    async with new_client("198.51.100.207") as admin:
        await make_admin(admin)
        domain = await add_active_domain(admin, scanner, host)
        did = domain["id"]
        project = (await admin.post("/api/v1/projects", json={"name": "R", "target_url": host})).json()
        assert project["verified"] is True

        # the proof disappears: the background re-check suspends the domain (audited)
        scanner.verify_ok = False
        counts = await recheck_trusted_domains({})
        assert counts["suspended"] >= 1 and counts["checked"] >= 1
        assert await domain_status(did) == "suspended"
        listed = {d["id"]: d for d in (await admin.get(TD)).json()}
        assert listed[did]["status"] == "suspended" and listed[did]["suspended_at"] is not None

        # rescan of the trusted_domain project → 422, and nothing is enqueued for the scanner
        before = await queued_scan_targets(redis)
        r = await admin.post(f"/api/v1/projects/{project['id']}/scans")
        assert r.status_code == 422 and r.json()["error"]["code"] == "trusted_domain_inactive"
        r = await admin.post(f"{TD}/{did}/scan")
        assert r.status_code == 422 and r.json()["error"]["code"] == "trusted_domain_inactive"
        assert await queued_scan_targets(redis) == before
        async with db_session(DbContext.system()) as session:
            scans = (
                await session.execute(
                    text("SELECT count(*) FROM scans WHERE project_id = :p"), {"p": project["id"]}
                )
            ).scalar_one()
        assert scans == 0

        # still gone on the next run: stays suspended, no second "suspended" audit row
        await recheck_trusted_domains({})
        assert await domain_status(did) == "suspended"

        # the proof is back: reactivated (audited), and the rescan goes through
        scanner.verify_ok = True
        counts = await recheck_trusted_domains({})
        assert counts["reactivated"] >= 1
        assert await domain_status(did) == "active"
        r = await admin.post(f"/api/v1/projects/{project['id']}/scans")
        assert r.status_code == 202, r.text
        assert (await queued_scan_targets(redis))[-1] == f"https://{host}"

    assert await audit_actions(str(did)) == [
        "admin.trusted_domain.added",
        "admin.trusted_domain.verified",
        "admin.trusted_domain.suspended",
        "admin.trusted_domain.reactivated",
    ]


async def test_manual_verify_failure_suspends_an_active_domain(redis: Redis, scanner: FakeScanner) -> None:
    async with new_client("198.51.100.208") as admin:
        await make_admin(admin)
        did = (await add_active_domain(admin, scanner, unique_host("manual")))["id"]
        scanner.verify_ok = False
        r = await admin.post(f"{TD}/{did}/verify")
        assert r.status_code == 422 and r.json()["error"]["code"] == "ownership_not_verified"
        assert await domain_status(did) == "suspended"
        scanner.verify_ok = True
        assert (await admin.post(f"{TD}/{did}/verify")).json()["status"] == "active"
    assert await audit_actions(str(did)) == [
        "admin.trusted_domain.added",
        "admin.trusted_domain.verified",
        "admin.trusted_domain.suspended",
        "admin.trusted_domain.reactivated",
    ]


async def test_stale_proof_is_not_trusted_until_proven_again(redis: Redis, scanner: FakeScanner) -> None:
    host = unique_host("stale")
    async with new_client("198.51.100.209") as admin:
        await make_admin(admin)
        did = (await add_active_domain(admin, scanner, host))["id"]
        async with db_session(DbContext.system()) as session:
            await session.execute(
                update(AdminTrustedDomain)
                .where(AdminTrustedDomain.id == uuid.UUID(did))
                .values(verified_at=datetime.now(UTC) - timedelta(days=31))
            )
        # an old proof doesn't verify a new project ...
        p = (await admin.post("/api/v1/projects", json={"name": "S", "target_url": host})).json()
        assert p["verified"] is False
        assert (await admin.delete(f"/api/v1/projects/{p['id']}")).status_code == 204
        # ... and "Scan now" proves it again first: proof gone → suspended, nothing queued
        scanner.verify_ok = False
        r = await admin.post(f"{TD}/{did}/scan")
        assert r.status_code == 422 and r.json()["error"]["code"] == "ownership_not_verified"
        assert await domain_status(did) == "suspended"
        assert await queued_scan_targets(redis) == []
        # proof still there → refreshed, then scanned
        async with db_session(DbContext.system()) as session:
            await session.execute(
                update(AdminTrustedDomain)
                .where(AdminTrustedDomain.id == uuid.UUID(did))
                .values(
                    status="active", suspended_at=None, verified_at=datetime.now(UTC) - timedelta(days=31)
                )
            )
        scanner.verify_ok = True
        r = await admin.post(f"{TD}/{did}/scan")
        assert r.status_code == 202, r.text
        assert await queued_scan_targets(redis) == [f"https://{host}"]


async def test_revoke_then_re_add(redis: Redis, scanner: FakeScanner) -> None:
    host = unique_host("revoke")
    async with new_client("198.51.100.210") as admin:
        await make_admin(admin)
        did = (await add_active_domain(admin, scanner, host))["id"]
        project = (await admin.post("/api/v1/projects", json={"name": "V", "target_url": host})).json()
        assert project["verified"] is True

        assert (await admin.delete(f"{TD}/{did}")).status_code == 204
        assert await domain_status(did) == "revoked"
        assert all(d["id"] != did for d in (await admin.get(TD)).json())
        for method, url in (
            ("POST", f"{TD}/{did}/verify"),
            ("POST", f"{TD}/{did}/scan"),
            ("DELETE", f"{TD}/{did}"),
        ):
            assert (await admin.request(method, url)).status_code == 404
        r = await admin.post(f"/api/v1/projects/{project['id']}/scans")
        assert r.status_code == 422 and r.json()["error"]["code"] == "trusted_domain_inactive"

        # the background re-check leaves revoked domains alone
        await recheck_trusted_domains({})
        assert await domain_status(did) == "revoked"

        again = await add_domain(admin, host)
        assert again["status"] == "pending" and again["id"] != did
        assert again["verification"] != {}
    assert await queued_scan_targets(redis) == []
    assert await audit_actions(str(did)) == [
        "admin.trusted_domain.added",
        "admin.trusted_domain.verified",
        "admin.trusted_domain.revoked",
    ]
    assert await audit_actions(str(again["id"])) == ["admin.trusted_domain.added"]


async def test_demoted_admin_loses_trusted_domains_immediately(redis: Redis, scanner: FakeScanner) -> None:
    host = unique_host("demote")
    async with new_client("198.51.100.211") as admin:
        email = await make_admin(admin)
        await add_active_domain(admin, scanner, host)
        project = (await admin.post("/api/v1/projects", json={"name": "D", "target_url": host})).json()
        assert project["verified"] is True
        await _set_role(email, "user")  # the session token still says admin; the DB wins
        assert (await admin.get(TD)).status_code == 404
        r = await admin.post(f"/api/v1/projects/{project['id']}/scans")
        assert r.status_code == 422 and r.json()["error"]["code"] == "trusted_domain_inactive"
        p = (
            await admin.post("/api/v1/projects", json={"name": "D2", "target_url": f"https://{host}:443"})
        ).json()
        assert p.get("error", {}).get("code") == "project_exists"
    assert await queued_scan_targets(redis) == []


async def test_internal_and_private_targets_are_refused(redis: Redis, scanner: FakeScanner) -> None:
    async with new_client("198.51.100.212") as admin:
        await make_admin(admin)
        for target in ("localhost", "http://10.0.0.1", "192.168.1.1:8080", "intranet.local", "db.internal",
                       "[::1]", "javascript:alert(1)", "https://user:pw@example.com"):  # fmt: skip
            r = await admin.post(TD, json={"target_url": target})
            assert r.status_code == 422, (target, r.text)
            assert r.json()["error"]["code"] == "invalid_target_url", target
        assert (await admin.get(TD)).json() == []
