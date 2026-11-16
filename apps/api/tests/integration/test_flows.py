"""End-to-end API flows against real PostgreSQL (RLS) + Redis with a fake scanner."""

from __future__ import annotations

import uuid

import pyotp
import pytest
from redis.asyncio import Redis
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from guardhub_api.admin.bootstrap import _set_role
from guardhub_api.db.models import Project
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.worker import consume_once, ensure_group, reap_stuck_scans

from .conftest import FakeScanner, new_client, next_code, raw_finding, signed_in


async def ingest(redis: Redis) -> None:
    await ensure_group(redis)
    for _ in range(5):
        await consume_once(redis, "test-worker", block_ms=50)


async def test_register_2fa_project_verify_rescan_report(redis: Redis, scanner: FakeScanner) -> None:
    async with new_client() as client:
        r = await client.post(
            "/api/v1/auth/register",
            json={"email": "Founder@Example.com", "password": "a-Strong-passphrase-42", "locale": "tr-TR"},
        )
        if r.status_code == 409:  # re-run against the same DB: use a fresh identity
            await signed_in(client)
        else:
            assert r.status_code == 201
            assert r.json()["mfa"] == "setup_required"
            assert r.json()["user"]["locale"] == "tr"
            # pre-MFA session can't reach the dashboard (§9.1)
            r = await client.get("/api/v1/projects")
            assert r.status_code == 403 and r.json()["error"]["code"] == "mfa_required"
            r = await client.post("/api/v1/auth/2fa/setup")
            secret = r.json()["secret"]
            assert r.json()["otpauth_uri"].startswith("otpauth://totp/GuardHub:")
            r = await client.post("/api/v1/auth/2fa/verify", json={"code": "000000"})
            assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_totp"
            r = await client.post("/api/v1/auth/2fa/verify", json={"code": pyotp.TOTP(secret).now()})
            assert r.status_code == 200 and r.json()["user"]["mfa_complete"] is True

        r = await client.post(
            "/api/v1/projects", json={"name": "Shop", "target_url": "Shop.Example.com/login"}
        )
        assert r.status_code == 201, r.text
        project = r.json()
        assert project["target_url"] == "https://shop.example.com"
        assert project["verified"] is False
        assert project["verification"]["dns_value"].startswith("guardhub-verify=ghv_")

        r = await client.post(f"/api/v1/projects/{project['id']}/scans")
        assert r.status_code == 422 and r.json()["error"]["code"] == "ownership_not_verified"

        r = await client.post(f"/api/v1/projects/{project['id']}/verify")
        assert r.status_code == 200 and r.json()["verified"] is True

        scanner.findings = [
            raw_finding(
                "exposed_env",
                "env_file_exposed",
                "https://shop.example.com/.env",
                {"path": "/.env", "secret_count": "4"},
            ),
            raw_finding("security_headers", "csp_missing", "https://shop.example.com/"),
            raw_finding(
                "exposed_env", "made_up_key", "https://shop.example.com/x"
            ),  # dropped: not in catalog
        ]
        r = await client.post(f"/api/v1/projects/{project['id']}/scans")
        assert r.status_code == 202, r.text
        scan_id = r.json()["id"]
        assert r.json()["status"] == "queued"

        r = await client.post(f"/api/v1/projects/{project['id']}/scans")
        assert r.status_code == 409 and r.json()["error"]["code"] == "scan_in_progress"

        await ingest(redis)
        r = await client.get(f"/api/v1/scans/{scan_id}?locale=tr")
        assert r.status_code == 200
        view = r.json()
        assert view["status"] == "done"
        assert view["score"] == 100 - 30 - 7
        assert view["finding_counts"]["critical"] == 1 and view["finding_counts"]["medium"] == 1
        assert [f["finding_key"] for f in view["findings"]] == ["env_file_exposed", "csp_missing"]
        top = view["findings"][0]
        assert top["severity"] == "critical"
        assert top["title"] and top["summary"] and top["why"] and top["fix"]
        assert top["evidence"]["redacted_payload"] == "API_KEY=****wxyz"  # decrypted for its owner
        assert all(p["status"] == "done" for p in view["progress"])
        assert len(view["progress"]) == 6

        en = (await client.get(f"/api/v1/scans/{scan_id}?locale=en")).json()["findings"][0]
        assert en["title"] != top["title"]  # curated tr text differs from en

        r = await client.get(f"/api/v1/projects/{project['id']}/scans")
        assert [s["id"] for s in r.json()] == [scan_id]

    # Evidence is encrypted at rest: the raw masked payload is not stored in plaintext.
    async with db_session(DbContext.system()) as session:
        stored = (
            (await session.execute(text("SELECT redacted_payload FROM evidence LIMIT 50"))).scalars().all()
        )
    assert stored and all(s.startswith("v1.") and "wxyz" not in s for s in stored)


async def test_rls_isolates_users(redis: Redis, scanner: FakeScanner) -> None:
    async with new_client("203.0.113.1") as alice, new_client("203.0.113.2") as bob:
        await signed_in(alice)
        await signed_in(bob)
        r = await alice.post("/api/v1/projects", json={"name": "A", "target_url": "alice-site.example"})
        project_id = r.json()["id"]
        r = await bob.get(f"/api/v1/projects/{project_id}")
        assert r.status_code == 404
        assert (await bob.get("/api/v1/projects")).json() == []
        assert (await bob.delete(f"/api/v1/projects/{project_id}")).status_code == 404
        assert (await bob.post(f"/api/v1/projects/{project_id}/verify")).status_code == 404
        me_bob = (await bob.get("/api/v1/auth/me")).json()

    # Even raw SQL in Bob's RLS context can't see Alice's row (the DB enforces it, not just the code).
    async with db_session(DbContext.for_user(uuid.UUID(me_bob["id"]), "user")) as session:
        rows = (await session.execute(select(Project).where(Project.id == uuid.UUID(project_id)))).all()
        assert rows == []
        count = (await session.execute(text("SELECT count(*) FROM users"))).scalar_one()
        assert count == 1  # only himself


async def test_anonymous_scan_requires_proof_then_claim(redis: Redis, scanner: FakeScanner) -> None:
    async with new_client("192.0.2.10") as anon:
        r = await anon.post("/api/v1/public/challenges", json={"target_url": "http://169.254.169.254"})
        assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_target_url"

        r = await anon.post("/api/v1/public/challenges", json={"target_url": "my-startup.example"})
        assert r.status_code == 201
        challenge = r.json()
        assert challenge["instructions"]["well_known_url"] == (
            "https://my-startup.example/.well-known/guardhub-verify.txt"
        )

        scanner.verify_ok = False
        r = await anon.post(f"/api/v1/public/challenges/{challenge['challenge_id']}/scan")
        assert r.status_code == 422 and r.json()["error"]["details"]["reason"] == "not_found"
        assert scanner.scan_jobs == []  # no proof → nothing was scanned

        scanner.verify_ok = True
        scanner.findings = [raw_finding("tls_cert", "https_unavailable", "my-startup.example:443")]
        r = await anon.post(f"/api/v1/public/challenges/{challenge['challenge_id']}/scan")
        assert r.status_code == 202
        started = r.json()
        await ingest(redis)

        url = f"/api/v1/public/scans/{started['scan_id']}"
        assert (await anon.get(url)).status_code == 422  # header required
        assert (await anon.get(url, headers={"X-Scan-Token": "ghs_wrong-token"})).status_code == 404
        r = await anon.get(url, headers={"X-Scan-Token": started["access_token"], "Accept-Language": "tr"})
        assert r.status_code == 200
        assert r.json()["status"] == "done" and r.json()["score"] == 85

    async with new_client("192.0.2.11") as user:
        await signed_in(user)
        r = await user.post(
            "/api/v1/projects/claim",
            json={"scan_id": started["scan_id"], "access_token": "ghs_wrong-token", "name": "Mine"},
        )
        assert r.status_code == 404
        r = await user.post(
            "/api/v1/projects/claim",
            json={
                "scan_id": started["scan_id"],
                "access_token": started["access_token"],
                "name": "My startup",
            },
        )
        assert r.status_code == 201, r.text
        project = r.json()
        assert project["verified"] is True  # the verified challenge carries over
        assert project["last_scan"]["id"] == started["scan_id"]
        assert (await user.get(f"/api/v1/scans/{started['scan_id']}")).status_code == 200

    async with new_client("192.0.2.10") as anon:  # the one-time public token is gone after claiming
        r = await anon.get(url, headers={"X-Scan-Token": started["access_token"]})
        assert r.status_code == 404


async def test_admin_requires_role_and_toggles_are_audited(redis: Redis, scanner: FakeScanner) -> None:
    async with new_client("198.51.100.50") as client:
        email, secret = await signed_in(client)
        assert (await client.get("/api/v1/admin/modules")).status_code == 404  # hidden from non-admins

        assert await _set_role(email, "admin") == 0
        modules = (await client.get("/api/v1/admin/modules")).json()
        assert {m["key"] for m in modules} >= {"exposed_env", "tls_cert"}

        r = await client.patch("/api/v1/admin/modules/info_leak", json={"enabled_global": False})
        assert r.status_code == 200 and r.json()["enabled_global"] is False
        checks = {c["id"]: c["enabled"] for c in (await client.get("/api/v1/checks")).json()}
        assert checks["info_leak"] is False and checks["exposed_env"] is True

        audit = (await client.get("/api/v1/admin/audit?limit=20")).json()
        assert any(a["action"] == "module.toggle" and a["target"] == "info_leak" for a in audit)
        assert (
            await client.patch("/api/v1/admin/modules/info_leak", json={"enabled_global": True})
        ).status_code == 200

        assert (await client.get("/api/v1/admin/ai")).json() == {
            "provider": None,
            "enabled": False,
            "active": False,
        }
        assert (await client.get("/api/v1/admin/users")).status_code == 200

        # logout revokes the session token server-side
        assert (await client.post("/api/v1/auth/logout")).status_code == 204
        assert (await client.get("/api/v1/auth/me")).status_code == 401

        # a fresh login needs the TOTP code again, and the old code can't be replayed
        r = await client.post(
            "/api/v1/auth/login", json={"email": email, "password": "a-Strong-passphrase-42"}
        )
        assert r.json() == {"mfa": "required"}
        assert (await client.get("/api/v1/admin/modules")).status_code == 403
        assert (
            await client.post("/api/v1/auth/2fa/verify", json={"code": next_code(secret)})
        ).status_code == 200
        assert (await client.get("/api/v1/admin/modules")).status_code == 200
        await _set_role(email, "user")
        assert (await client.get("/api/v1/admin/modules")).status_code == 404  # demotion is immediate


async def test_login_failures_are_rate_limited_and_audited(redis: Redis) -> None:
    async with new_client("198.51.100.99") as client:
        email, _ = await signed_in(client)
        codes = []
        for _ in range(11):
            r = await client.post(
                "/api/v1/auth/login", json={"email": email, "password": "wrong-password-123"}
            )
            codes.append(r.status_code)
        assert codes[:10] == [401] * 10 and codes[10] == 429
    async with db_session(DbContext.system()) as session:
        n = (
            await session.execute(text("SELECT count(*) FROM audit_logs WHERE action = 'auth.login_failed'"))
        ).scalar_one()
    assert n >= 10


async def test_audit_log_is_append_only(redis: Redis) -> None:
    for stmt in ("UPDATE audit_logs SET action = 'x'", "DELETE FROM audit_logs"):
        with pytest.raises(DBAPIError):
            async with db_session(DbContext.system()) as session:
                await session.execute(text(stmt))


async def test_failed_scan_and_reaper(redis: Redis, scanner: FakeScanner) -> None:
    async with new_client("198.51.100.120") as client:
        await signed_in(client)
        project = (
            await client.post("/api/v1/projects", json={"name": "F", "target_url": "fail.example"})
        ).json()
        await client.post(f"/api/v1/projects/{project['id']}/verify")
        scanner.fail_scan = "target_unreachable"
        scan_id = (await client.post(f"/api/v1/projects/{project['id']}/scans")).json()["id"]
        await ingest(redis)
        view = (await client.get(f"/api/v1/scans/{scan_id}")).json()
        assert view["status"] == "failed" and view["error"] == "target_unreachable"
    assert await reap_stuck_scans() >= 0
