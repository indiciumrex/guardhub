"""Per-check success/failure counters in Redis (hourly buckets, 2h TTL) for module health (§8.5)."""

from __future__ import annotations

import time

from redis.asyncio import Redis


def _bucket(now: float | None = None) -> int:
    return int((now or time.time()) // 3600)


async def record_check_result(redis: Redis, check_id: str, *, ok: bool) -> None:
    key = f"gh:health:check:{check_id}:{'ok' if ok else 'fail'}:{_bucket()}"
    async with redis.pipeline(transaction=False) as pipe:
        pipe.incr(key)
        pipe.expire(key, 7200)
        await pipe.execute()


async def check_error_rate(redis: Redis, check_id: str) -> tuple[float, int]:
    """Return (error_rate, samples) over the current and previous hour."""
    b = _bucket()
    keys = [f"gh:health:check:{check_id}:{kind}:{h}" for kind in ("ok", "fail") for h in (b, b - 1)]
    vals = [int(v or 0) for v in await redis.mget(keys)]
    ok, fail = vals[0] + vals[1], vals[2] + vals[3]
    total = ok + fail
    return (fail / total if total else 0.0), total
