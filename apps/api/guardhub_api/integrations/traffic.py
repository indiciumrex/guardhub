"""Endpoint traffic (Admin Panel, Prompt 2 §4): requests, 4xx, 5xx, 429 and latency per route,
in hourly Redis hashes (48 h TTL), recorded by the request middleware. Recording never raises.

Routes are their templates (`/api/v1/scans/{scan_id}`), never raw paths, so no identifier or
query string is stored. Latency is kept as a sum and a small histogram for an approximate p95.
"""

from __future__ import annotations

import logging
import time

from pydantic import BaseModel
from redis.asyncio import Redis

log = logging.getLogger(__name__)
PREFIX = "gh:ops:traffic:"
TTL_SECONDS = 48 * 3600
BUCKETS_MS = (50, 100, 250, 500, 1000, 2500, 5000)


def _hour(now: float | None = None) -> int:
    return int((now or time.time()) // 3600)


def _bucket(ms: float) -> str:
    for b in BUCKETS_MS:
        if ms <= b:
            return str(b)
    return "inf"


async def record(redis: Redis, *, method: str, route: str, status: int, latency_ms: float) -> None:
    key = f"{PREFIX}{_hour()}"
    name = f"{method} {route}"
    try:
        async with redis.pipeline(transaction=False) as pipe:
            pipe.hincrby(key, f"{name}|n", 1)
            pipe.hincrby(key, f"{name}|ms", int(latency_ms))
            pipe.hincrby(key, f"{name}|b{_bucket(latency_ms)}", 1)
            if 400 <= status < 500:
                pipe.hincrby(key, f"{name}|4xx", 1)
            if status >= 500:
                pipe.hincrby(key, f"{name}|5xx", 1)
            if status == 429:
                pipe.hincrby(key, f"{name}|429", 1)
            pipe.expire(key, TTL_SECONDS)
            await pipe.execute()
    except Exception:
        log.warning("traffic_record_failed")


class EndpointTraffic(BaseModel):
    endpoint: str
    requests: int
    client_errors: int
    server_errors: int
    rate_limited: int
    error_rate: float
    avg_ms: int
    p95_ms: int | None  # upper bound of the bucket holding the 95th percentile; None above 5 s


def _p95(buckets: dict[str, int], n: int) -> int | None:
    seen = 0
    for b in (*[str(x) for x in BUCKETS_MS], "inf"):
        seen += buckets.get(b, 0)
        if n and seen >= 0.95 * n:
            return None if b == "inf" else int(b)
    return None


async def summary(redis: Redis, hours: int, now: float | None = None) -> list[EndpointTraffic]:
    end = _hour(now)
    totals: dict[str, dict[str, int]] = {}
    for h in range(end - hours + 1, end + 1):
        for field, value in (await redis.hgetall(f"{PREFIX}{h}")).items():
            f = field.decode() if isinstance(field, bytes) else str(field)
            name, _, metric = f.rpartition("|")
            totals.setdefault(name, {})
            totals[name][metric] = totals[name].get(metric, 0) + int(value)
    rows = []
    for name, m in totals.items():
        n = m.get("n", 0)
        buckets = {k[1:]: v for k, v in m.items() if k.startswith("b")}
        rows.append(
            EndpointTraffic(
                endpoint=name,
                requests=n,
                client_errors=m.get("4xx", 0),
                server_errors=m.get("5xx", 0),
                rate_limited=m.get("429", 0),
                error_rate=round(m.get("5xx", 0) / n, 4) if n else 0.0,
                avg_ms=int(m.get("ms", 0) / n) if n else 0,
                p95_ms=_p95(buckets, n),
            )
        )
    return sorted(rows, key=lambda r: (-r.requests, r.endpoint))
