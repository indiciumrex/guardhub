"""Database engine and RLS-scoped sessions.

Every unit of work runs in a transaction that FIRST sets the transaction-local RLS settings
(`app.role`, `app.user_id`, `app.scan_token`) that the policies in ops/migrations read, so a
forgotten WHERE clause can't leak another user's rows. `DbContext` names the caller explicitly.
The 'system' role is reserved for narrow internal paths (login lookup, event ingestion,
anonymous-challenge handling) and is never derived from user input.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from guardhub_api.config import get_settings

Role = Literal["user", "admin", "system", "anon"]


@dataclass(frozen=True, slots=True)
class DbContext:
    role: Role
    user_id: uuid.UUID | None = None
    scan_token_hash: str | None = None

    @staticmethod
    def system() -> DbContext:
        return DbContext(role="system")

    @staticmethod
    def for_user(user_id: uuid.UUID, role: str) -> DbContext:
        return DbContext(role="admin" if role == "admin" else "user", user_id=user_id)

    @staticmethod
    def anon(scan_token_hash: str) -> DbContext:
        return DbContext(role="anon", scan_token_hash=scan_token_hash)


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine, _sessionmaker  # noqa: PLW0603 — process-wide pool
    if _engine is None:
        _engine = create_async_engine(
            get_settings().database_url.get_secret_value(),
            pool_size=10,
            max_overflow=10,
            pool_pre_ping=True,
        )
        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine, _sessionmaker = None, None


@asynccontextmanager
async def db_session(ctx: DbContext) -> AsyncIterator[AsyncSession]:
    """Open a transaction bound to `ctx`. Commits on success, rolls back on error."""
    get_engine()
    assert _sessionmaker is not None
    async with _sessionmaker() as session, session.begin():
        await session.execute(
            text(
                "SELECT set_config('app.role', :role, true), "
                "set_config('app.user_id', :uid, true), "
                "set_config('app.scan_token', :tok, true)"
            ),
            {
                "role": ctx.role,
                "uid": str(ctx.user_id) if ctx.user_id else "",
                "tok": ctx.scan_token_hash or "",
            },
        )
        yield session
