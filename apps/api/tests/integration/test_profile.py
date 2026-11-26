"""Own profile and password (profile prompt, item 1) against real PostgreSQL + Redis: the display
name is the holder's own; a password change needs the current password AND a current two-factor
code, is audited (failures too), ends the other sessions and keeps this one."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import httpx
import pyotp
import pytest
from redis.asyncio import Redis
from sqlalchemy import select

from guardhub_api.db.models import AuditLog, User
from guardhub_api.db.session import DbContext, db_session

from .conftest import new_client, next_code, signed_in

PASSWORD = "a-Strong-passphrase-42"
NEW_PASSWORD = "another-Long-passphrase-77"


@pytest.fixture(autouse=True)
async def _fresh_rate_limits(redis: Redis) -> AsyncIterator[None]:
    yield


async def _user(email: str) -> User:
    async with db_session(DbContext.system()) as session:
        return (await session.execute(select(User).where(User.email == email))).scalar_one()


async def _actions(user_id: uuid.UUID) -> list[str]:
    async with db_session(DbContext.system()) as session:
        rows = await session.execute(select(AuditLog.action).where(AuditLog.target == str(user_id)))
        return list(rows.scalars())


async def test_display_name_is_own_and_trimmed(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    r = await client.patch("/api/v1/auth/me", json={"display_name": "  Ada   Lovelace "})
    assert r.status_code == 200 and r.json()["display_name"] == "Ada Lovelace"
    assert r.json()["role"] == "user"
    assert (await client.get("/api/v1/auth/me")).json()["display_name"] == "Ada Lovelace"
    r = await client.patch("/api/v1/auth/me", json={"display_name": "bad\u0007name"})
    assert r.status_code == 422
    r = await client.patch("/api/v1/auth/me", json={"display_name": ""})
    assert r.status_code == 200 and r.json()["display_name"] is None
    # The profile cannot carry a role: unknown fields are ignored, the role stays "user".
    r = await client.patch("/api/v1/auth/me", json={"role": "admin", "locale": "en"})
    assert r.status_code == 200 and r.json()["role"] == "user"


async def test_display_name_needs_a_full_session() -> None:
    async with new_client("198.51.100.91") as pre:
        email = f"pn-{uuid.uuid4().hex[:8]}@example.com"
        r = await pre.post(
            "/api/v1/auth/register", json={"email": email, "password": PASSWORD, "locale": "en"}
        )
        assert r.status_code == 201
        assert (await pre.patch("/api/v1/auth/me", json={"locale": "tr"})).status_code == 200
        assert (await pre.patch("/api/v1/auth/me", json={"display_name": "X"})).status_code == 403
        assert (
            await pre.post(
                "/api/v1/auth/password",
                json={"current_password": PASSWORD, "new_password": NEW_PASSWORD, "code": "123456"},
            )
        ).status_code == 403  # a pre-MFA session cannot change the password


async def test_password_change_needs_password_and_code_and_ends_other_sessions(
    client: httpx.AsyncClient, redis: Redis
) -> None:
    email, secret = await signed_in(client)
    user = await _user(email)
    async with new_client("198.51.100.92") as laptop:
        assert (
            await laptop.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        ).status_code == 200
        r = await laptop.post("/api/v1/auth/2fa/verify", json={"code": next_code(secret)})
        assert r.status_code == 200
        assert (await laptop.get("/api/v1/auth/me")).status_code == 200

        url = "/api/v1/auth/password"
        # Wrong current password: refused even with a valid code.
        r = await client.post(
            url,
            json={"current_password": "wrong-one-entirely", "new_password": NEW_PASSWORD, "code": "000000"},
        )
        assert r.status_code == 401 and r.json()["error"]["code"] == "wrong_current_password"
        # Right password, wrong code: refused.
        r = await client.post(
            url, json={"current_password": PASSWORD, "new_password": NEW_PASSWORD, "code": "000000"}
        )
        assert r.status_code == 401 and r.json()["error"]["code"] == "invalid_totp"
        # Weak new password: refused by the same policy as sign-up.
        await redis.delete(f"gh:totp:last:{user.id}")  # the test spent the codes above in one window
        r = await client.post(
            url,
            json={"current_password": PASSWORD, "new_password": "short", "code": pyotp.TOTP(secret).now()},
        )
        assert r.status_code == 422 and r.json()["error"]["code"] == "weak_password"
        # Everything right: changed, the laptop's session ends, this one stays.
        await redis.delete(f"gh:totp:last:{user.id}")
        r = await client.post(
            url,
            json={
                "current_password": PASSWORD,
                "new_password": NEW_PASSWORD,
                "code": pyotp.TOTP(secret).now(),
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["sessions_ended"] == 1
        assert (await laptop.get("/api/v1/auth/me")).status_code == 401
        me = (await client.get("/api/v1/auth/me")).json()
        assert me["password_changed_at"] is not None

    async with new_client("198.51.100.93") as fresh:
        old = await fresh.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert old.status_code == 401
        new = await fresh.post("/api/v1/auth/login", json={"email": email, "password": NEW_PASSWORD})
        assert new.status_code == 200

    actions = await _actions(user.id)
    assert actions.count("auth.password_change_failed") == 3
    assert actions.count("auth.password_changed") == 1


async def test_password_change_is_rate_limited(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    body = {"current_password": "wrong-one-entirely", "new_password": NEW_PASSWORD, "code": "000000"}
    codes = [(await client.post("/api/v1/auth/password", json=body)).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
