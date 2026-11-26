"""Database guard for users.role / disabled state (migration 0025), on the application role:
a customer context cannot change them, the system context (operator CLI) and admin context can."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime

import httpx
import pytest
from redis.asyncio import Redis
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from guardhub_api.admin.bootstrap import _set_role
from guardhub_api.db.models import User
from guardhub_api.db.session import DbContext, db_session

from .conftest import signed_in


@pytest.fixture(autouse=True)
async def _fresh_rate_limits(redis: Redis) -> AsyncIterator[None]:
    yield


async def _user(email: str) -> User:
    async with db_session(DbContext.system()) as session:
        return (await session.execute(select(User).where(User.email == email))).scalar_one()


@pytest.mark.parametrize(
    "stmt",
    [
        "UPDATE users SET role = 'admin' WHERE id = :id",
        "UPDATE users SET disabled_at = now() WHERE id = :id",
        "UPDATE users SET disabled_by = id WHERE id = :id",
    ],
)
async def test_a_customer_context_cannot_change_privileged_columns(
    client: httpx.AsyncClient, stmt: str
) -> None:
    email, _ = await signed_in(client)
    user = await _user(email)
    with pytest.raises(DBAPIError, match="admin or system context"):
        async with db_session(DbContext(role="user", user_id=user.id)) as session:
            await session.execute(text(stmt), {"id": user.id})
    assert (await _user(email)).role == "user"


async def test_a_customer_context_still_updates_its_own_harmless_columns(client: httpx.AsyncClient) -> None:
    email, _ = await signed_in(client)
    user = await _user(email)
    async with db_session(DbContext(role="user", user_id=user.id)) as session:
        await session.execute(
            text("UPDATE users SET locale = 'tr', last_login_at = now() WHERE id = :id"), {"id": user.id}
        )
    assert (await _user(email)).locale == "tr"


async def test_a_customer_context_cannot_insert_an_admin() -> None:
    with pytest.raises(DBAPIError, match="plain customer"):
        async with db_session(DbContext(role="user")) as session:
            await session.execute(
                text(
                    "INSERT INTO users (email, password_hash, role) VALUES ('sneaky@example.com', 'x', 'admin')"
                )
            )


async def test_the_operator_cli_and_admin_context_still_work(client: httpx.AsyncClient) -> None:
    email, _ = await signed_in(client)
    assert await _set_role(email, "admin") == 0  # system context
    assert (await _user(email)).role == "admin"
    user = await _user(email)
    async with db_session(DbContext(role="admin", user_id=user.id)) as session:
        row = await session.get(User, user.id)
        assert row is not None
        row.disabled_at = datetime.now(UTC)
    async with db_session(DbContext.system()) as session:
        row = await session.get(User, user.id)
        assert row is not None and row.disabled_at is not None
        row.disabled_at = None
    assert await _set_role(email, "user") == 0
