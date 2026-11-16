"""Shared async Redis client (queue, rate limits, progress, session denylist)."""

from __future__ import annotations

from redis.asyncio import Redis

from guardhub_api.config import get_settings

_client: Redis | None = None


def get_redis() -> Redis:
    global _client  # noqa: PLW0603 — process-wide connection pool
    if _client is None:
        _client = Redis.from_url(
            get_settings().redis_url.get_secret_value(),
            decode_responses=True,
            socket_timeout=10,
            socket_connect_timeout=5,
            health_check_interval=30,
        )
    return _client


def set_redis(client: Redis | None) -> None:
    """Override the client (tests)."""
    global _client  # noqa: PLW0603
    _client = client


async def close_redis() -> None:
    global _client  # noqa: PLW0603
    if _client is not None:
        await _client.aclose()
        _client = None
