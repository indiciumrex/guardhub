"""Two-factor recovery (Admin Panel gaps) against real PostgreSQL + Redis: ten single-use codes
shown once at setup, sign-in with a code, regeneration with a current code, and a reset by
another admin who confirms with their own code (never by yourself)."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pyotp
import pytest
from redis.asyncio import Redis
from sqlalchemy import select

from guardhub_api.config import get_settings
from guardhub_api.db.models import AuditLog, User
from guardhub_api.db.session import DbContext, db_session

from .conftest import new_client, next_code
from .test_active import make_admin

PASSWORD = "a-Strong-passphrase-42"


@pytest.fixture(autouse=True)
async def _fresh_rate_limits(redis: Redis) -> AsyncIterator[None]:
    yield


async def _enroll(client: httpx.AsyncClient) -> tuple[str, str, list[str]]:
    email = f"rc-{uuid.uuid4().hex[:10]}@example.com"
    r = await client.post(
        "/api/v1/auth/register", json={"email": email, "password": PASSWORD, "locale": "en"}
    )
    assert r.status_code == 201
    secret = (await client.post("/api/v1/auth/2fa/setup")).json()["secret"]
    r = await client.post("/api/v1/auth/2fa/verify", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200
    codes = r.json()["recovery_codes"]
    return email, secret, codes


async def test_codes_once_at_setup_and_each_works_once(client: httpx.AsyncClient) -> None:
    email, _, codes = await _enroll(client)
    assert len(codes) == 10 and len(set(codes)) == 10
    assert (await client.get("/api/v1/auth/2fa/recovery-codes")).json() == {"remaining": 10}
    await client.post("/api/v1/auth/logout")
    async with new_client("198.51.100.81") as other:
        assert (
            await other.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        ).status_code == 200
        r = await other.post("/api/v1/auth/2fa/recover", json={"code": codes[0].upper()})
        assert r.status_code == 200 and r.json()["recovery_codes"] is None
        assert (await other.get("/api/v1/auth/me")).status_code == 200
        assert (await other.get("/api/v1/auth/2fa/recovery-codes")).json() == {"remaining": 9}
    async with new_client("198.51.100.82") as again:
        await again.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        r = await again.post("/api/v1/auth/2fa/recover", json={"code": codes[0]})
        assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_recovery_code"
        r = await again.post("/api/v1/auth/2fa/recover", json={"code": "aaaaa-bbbbb"})
        assert r.status_code == 401


async def test_regenerating_needs_a_current_code_and_voids_the_old_ones(client: httpx.AsyncClient) -> None:
    email, secret, old = await _enroll(client)
    r = await client.post("/api/v1/auth/2fa/recovery-codes", json={"code": "000000"})
    assert r.status_code == 401
    r = await client.post("/api/v1/auth/2fa/recovery-codes", json={"code": next_code(secret)})
    assert r.status_code == 200
    fresh = r.json()["codes"]
    assert len(fresh) == 10 and not set(fresh) & set(old)
    async with new_client("198.51.100.83") as other:
        await other.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert (await other.post("/api/v1/auth/2fa/recover", json={"code": old[1]})).status_code == 401
        assert (await other.post("/api/v1/auth/2fa/recover", json={"code": fresh[0]})).status_code == 200


async def test_another_admin_resets_with_their_own_code_never_yourself(client: httpx.AsyncClient) -> None:
    async with new_client("198.51.100.84") as target:
        email, _, _ = await _enroll(target)
        async with db_session(DbContext.system()) as session:
            target_id = (await session.execute(select(User.id).where(User.email == email))).scalar_one()

        admin_email = await make_admin(client)
        async with db_session(DbContext.system()) as session:
            admin = (await session.execute(select(User).where(User.email == admin_email))).scalar_one()
        # the admin's own secret is not known to this test client: read it the way the API does
        admin_secret = get_settings().keyring.decrypt(
            admin.totp_secret or "", associated_data=str(admin.id).encode()
        )

        r = await client.post(f"/api/v1/admin/people/{admin.id}/reset-two-factor",
                              json={"reason": "lost phone", "code": "123456"})  # fmt: skip
        assert r.status_code == 422 and r.json()["error"]["code"] == "cannot_reset_self"
        r = await client.post(f"/api/v1/admin/people/{target_id}/reset-two-factor",
                              json={"reason": "lost phone", "code": "000000"})  # fmt: skip
        assert r.status_code == 401
        r = await client.post(f"/api/v1/admin/people/{target_id}/reset-two-factor",
                              json={"reason": "lost phone", "code": next_code(admin_secret)})  # fmt: skip
        assert r.status_code == 200, r.text
        assert r.json()["sessions_ended"] >= 1
        assert (await target.get("/api/v1/auth/me")).status_code == 401

    async with new_client("198.51.100.85") as target:
        r = await target.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert r.json() == {"mfa": "setup_required"}  # set up two-factor again
    async with db_session(DbContext.system()) as session:
        actions = set((await session.execute(select(AuditLog.action).where(AuditLog.target == str(target_id))))
                      .scalars().all())  # fmt: skip
    assert "user.two_factor_reset" in actions
