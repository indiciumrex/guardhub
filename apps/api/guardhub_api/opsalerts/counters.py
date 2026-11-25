"""API 5xx counter (per-minute buckets in Redis, 2 h TTL) behind the `api_errors` alert rule.
Counting must never break a request: any Redis problem is swallowed."""

from __future__ import annotations

import logging
import time

from redis.asyncio import Redis

log = logging.getLogger(__name__)
PREFIX = "gh:ops:api5xx:"
TTL_SECONDS = 2 * 3600


def _minute(now: float | None = None) -> int:
    return int((now or time.time()) // 60)


async def count_5xx(redis: Redis) -> None:
    key = f"{PREFIX}{_minute()}"
    try:
        async with redis.pipeline(transaction=False) as pipe:
            pipe.incr(key)
            pipe.expire(key, TTL_SECONDS)
            await pipe.execute()
    except Exception:
        log.warning("api_5xx_count_failed")


async def errors_in_window(redis: Redis, minutes: int, now: float | None = None) -> int:
    end = _minute(now)
    keys = [f"{PREFIX}{m}" for m in range(end - minutes + 1, end + 1)]
    return sum(int(v or 0) for v in await redis.mget(keys))
