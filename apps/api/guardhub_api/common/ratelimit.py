"""Distributed fixed-window rate limiting on Redis (§3: Redis does rate-limit).

`enforce(bucket, key, limit, window)` raises RateLimitedError once `limit` hits within `window`
seconds. Keys are hashed by the caller when they contain personal data (IP, email).
"""

from __future__ import annotations

import time

from redis.asyncio import Redis

from guardhub_api.common.errors import RateLimitedError


async def hit(redis: Redis, bucket: str, key: str, limit: int, window: int) -> tuple[bool, int]:
    """Count one hit. Returns (allowed, retry_after_seconds)."""
    now = int(time.time())
    window_start = now - (now % window)
    rkey = f"gh:rl:{bucket}:{key}:{window_start}"
    async with redis.pipeline(transaction=True) as pipe:
        pipe.incr(rkey)
        pipe.expire(rkey, window + 5)
        count, _ = await pipe.execute()
    retry_after = window_start + window - now
    return int(count) <= limit, max(1, retry_after)


async def enforce(redis: Redis, bucket: str, key: str, limit: int, window: int) -> None:
    allowed, retry_after = await hit(redis, bucket, key, limit, window)
    if not allowed:
        raise RateLimitedError(retry_after)


async def reset(redis: Redis, bucket: str, key: str, window: int) -> None:
    now = int(time.time())
    await redis.delete(f"gh:rl:{bucket}:{key}:{now - (now % window)}")
