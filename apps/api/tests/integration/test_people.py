"""Users & sessions (Prompt 2 §5) against real PostgreSQL + Redis: disabling ends sessions,
sign-in and API keys; sessions are listed and ended; failed sign-ins are visible; an admin
invitation works only for the invited e-mail after two-factor sign-in, once."""

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
from .test_active import make_admin

PEOPLE = "/api/v1/admin/people"
PASSWORD = "a-Strong-passphrase-42"


@pytest.fixture(autouse=True)
async def _fresh_rate_limits(redis: Redis) -> AsyncIterator[None]:
    """Every test registers users from the same test address: start each with fresh rate limits."""
    yield


async def _id(email: str) -> uuid.UUID:
    async with db_session(DbContext.system()) as session:
        return (await session.execute(select(User.id).where(User.email == email))).scalar_one()


async def test_disabling_ends_sessions_sign_in_and_keys(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    async with new_client("198.51.100.61") as customer:
        email, _ = await signed_in(customer)
        user_id = await _id(email)
        sessions = (await client.get(f"{PEOPLE}/{user_id}/sessions")).json()
        assert len(sessions) == 1 and sessions[0]["client"]

        r = await client.post(f"{PEOPLE}/{user_id}/disable", json={"reason": "abuse report"})
        assert r.status_code == 200 and r.json()["sessions_ended"] == 1
        assert (await customer.get("/api/v1/auth/me")).status_code == 401  # the live session is gone
        r = await customer.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert r.status_code == 403 and r.json()["error"]["code"] == "account_disabled"
        r = await customer.post("/api/v1/auth/login", json={"email": email, "password": "wrong-Password-1"})
        assert r.status_code == 401  # a wrong password never reveals the account state

        users = (await client.get("/api/v1/admin/users?limit=200")).json()
        row = next(u for u in users if u["id"] == str(user_id))
        assert row["disabled_at"] is not None and row["last_login_at"] is not None

        assert (await client.post(f"{PEOPLE}/{user_id}/enable")).status_code == 200
        r = await customer.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert r.status_code == 200


async def test_an_admin_cannot_disable_themselves_and_a_disabled_admins_keys_stop(
    client: httpx.AsyncClient,
) -> None:
    me = await make_admin(client)
    r = await client.post(f"{PEOPLE}/{await _id(me)}/disable", json={})
    assert r.status_code == 422 and r.json()["error"]["code"] == "cannot_disable_self"
    async with new_client("198.51.100.62") as other:
        other_email = await make_admin(other)
        r = await other.post(
            "/api/v1/admin/integrations/keys",
            json={"name": "k", "scopes": ["projects:read"], "expires_in_days": 30},
        )
        secret = r.json()["secret"]
    headers = {"Authorization": f"Bearer {secret}"}
    async with new_client("198.51.100.63") as tool:
        assert (await tool.get("/api/v1/integrations/projects", headers=headers)).status_code == 200
        assert (await client.post(f"{PEOPLE}/{await _id(other_email)}/disable", json={})).status_code == 200
        assert (await tool.get("/api/v1/integrations/projects", headers=headers)).status_code == 401


async def test_end_one_or_all_sessions(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    async with new_client("198.51.100.64") as phone, new_client("198.51.100.65") as laptop:
        email, secret = await signed_in(phone)
        r = await laptop.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
        assert r.status_code == 200
        assert (
            await laptop.post("/api/v1/auth/2fa/verify", json={"code": next_code(secret)})
        ).status_code == 200
        user_id = await _id(email)
        listed = (await client.get(f"{PEOPLE}/{user_id}/sessions")).json()
        assert len(listed) == 2
        r = await client.post(f"{PEOPLE}/{user_id}/sessions/end", json={"jti": listed[0]["jti"]})
        assert r.json()["sessions_ended"] == 1
        alive = [(await c.get("/api/v1/auth/me")).status_code for c in (phone, laptop)]
        assert sorted(alive) == [200, 401]
        r = await client.post(f"{PEOPLE}/{user_id}/sessions/end", json={})
        assert r.json()["sessions_ended"] == 1
        assert [(await c.get("/api/v1/auth/me")).status_code for c in (phone, laptop)] == [401, 401]


async def test_failed_sign_ins_are_listed(client: httpx.AsyncClient) -> None:
    await make_admin(client)
    async with new_client("198.51.100.66") as someone:
        email, _ = await signed_in(someone)
        await someone.post("/api/v1/auth/login", json={"email": email, "password": "not-the-Password-9"})
    data = (await client.get(f"{PEOPLE}/security/failed-sign-ins?hours=1")).json()
    assert data["total"] >= 1
    assert data["by_account"].get(email, 0) >= 1
    assert any(f["account"] == email and f["kind"] == "password" and f["ip_hash"] for f in data["recent"])


async def test_admin_invitation_only_for_the_invited_email_after_2fa_and_once(
    client: httpx.AsyncClient,
) -> None:
    await make_admin(client)
    invited = f"invited-{uuid.uuid4().hex[:8]}@example.com"
    r = await client.post(f"{PEOPLE}/invites", json={"email": invited})
    assert r.status_code == 201
    link = r.json()["link"]
    token = link.split("token=", 1)[1]
    assert "/account/admin-invite?token=ghi_" in link

    async with new_client("198.51.100.67") as wrong:
        await signed_in(wrong)
        r = await wrong.post("/api/v1/auth/admin-invite/accept", json={"token": token})
        assert r.status_code == 403 and r.json()["error"]["code"] == "invite_wrong_account"

    async with new_client("198.51.100.68") as person:
        r = await person.post(
            "/api/v1/auth/register", json={"email": invited, "password": PASSWORD, "locale": "en"}
        )
        assert r.status_code == 201
        r = await person.post("/api/v1/auth/admin-invite/accept", json={"token": token})
        assert r.status_code == 403  # a pre-2FA session cannot accept
        await person.post("/api/v1/auth/logout")
    async with new_client("198.51.100.69") as person:
        r = await person.post("/api/v1/auth/login", json={"email": invited, "password": PASSWORD})
        assert r.status_code == 200
        setup = (await person.post("/api/v1/auth/2fa/setup")).json()
        r = await person.post("/api/v1/auth/2fa/verify", json={"code": pyotp.TOTP(setup["secret"]).now()})
        assert r.status_code == 200
        r = await person.post("/api/v1/auth/admin-invite/accept", json={"token": token})
        assert r.status_code == 200 and r.json() == {"role": "admin"}
        assert (await person.get("/api/v1/admin/overview")).status_code == 200
        r = await person.post("/api/v1/auth/admin-invite/accept", json={"token": token})
        assert r.status_code == 404 and r.json()["error"]["code"] == "invite_invalid"

    later = (await client.post(f"{PEOPLE}/invites", json={"email": "later@example.com"})).json()
    revoked = await client.post(f"{PEOPLE}/invites/{later['invite']['id']}/revoke")
    assert revoked.json()["status"] == "revoked"
    async with db_session(DbContext.system()) as session:
        actions = set(
            (
                await session.execute(select(AuditLog.action).where(AuditLog.action.like("admin_invite.%")))
            ).scalars()
        )
    assert {"admin_invite.created", "admin_invite.accepted", "admin_invite.revoked"} <= actions


async def test_people_routes_are_admin_only(client: httpx.AsyncClient) -> None:
    await signed_in(client)
    assert (await client.get(f"{PEOPLE}/invites")).status_code == 404
    assert (await client.get(f"{PEOPLE}/security/failed-sign-ins")).status_code == 404
