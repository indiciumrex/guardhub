"""Alembic environment: runs SQL migrations as the database OWNER role (never the app role)."""

from __future__ import annotations

import asyncio
import os

from alembic import context
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine


def _url() -> str:
    url = os.environ.get("MIGRATIONS_DATABASE_URL")
    if not url:
        raise SystemExit("MIGRATIONS_DATABASE_URL is required (owner role, postgresql+asyncpg://...)")
    return url


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=None, transaction_per_migration=True)
    with context.begin_transaction():
        context.run_migrations()


async def _main() -> None:
    engine = create_async_engine(_url())
    async with engine.connect() as conn:
        await conn.run_sync(_run)
        await conn.commit()
    await engine.dispose()


if context.is_offline_mode():
    raise SystemExit("offline mode is not supported")
asyncio.run(_main())
