"""System self-monitoring (§8.5). Plain infrastructure that never uses or needs AI.

- `live_status`: the fast probe used by GET /health (database, Redis, scanner liveness).
- `snapshot`: run periodically by the worker. It records a HealthCheck row per component and per
  check module (error rate from scan results) for the admin panel.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import HealthCheck
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.contract_gen import CHECK_IDS
from guardhub_api.health.counters import check_error_rate
from guardhub_api.scans.queue import scanner_alive

log = logging.getLogger("guardhub.health")

ComponentStatus = Literal["ok", "degraded", "down", "unknown"]
RETENTION = timedelta(days=7)


class LiveHealth(BaseModel):
    status: Literal["ok", "degraded", "down"]
    components: dict[str, ComponentStatus]


class HealthRow(BaseModel):
    module_key: str
    status: str
    error_rate: float
    latency_ms: int
    checked_at: datetime


async def _db_latency_ms() -> int | None:
    start = time.perf_counter()
    try:
        async with db_session(DbContext.system()) as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        log.warning("health_db_down", exc_info=True)
        return None
    return int((time.perf_counter() - start) * 1000)


async def _redis_latency_ms(redis: Redis) -> int | None:
    start = time.perf_counter()
    try:
        await redis.ping()
    except Exception:
        log.warning("health_redis_down", exc_info=True)
        return None
    return int((time.perf_counter() - start) * 1000)


async def live_status(redis: Redis) -> LiveHealth:
    db_ms = await _db_latency_ms()
    redis_ms = await _redis_latency_ms(redis)
    scanner: ComponentStatus = "unknown"
    if redis_ms is not None:
        alive = await scanner_alive(redis)
        scanner = "unknown" if alive is None else ("ok" if alive else "down")
    components: dict[str, ComponentStatus] = {
        "database": "ok" if db_ms is not None else "down",
        "redis": "ok" if redis_ms is not None else "down",
        "scanner": scanner,
    }
    if components["database"] == "down" or components["redis"] == "down":
        overall: Literal["ok", "degraded", "down"] = "down"
    elif scanner != "ok":
        overall = "degraded"
    else:
        overall = "ok"
    return LiveHealth(status=overall, components=components)


def _rate_status(error_rate: float, samples: int) -> str:
    if samples < 5 or error_rate < 0.2:
        return "ok"
    return "degraded" if error_rate < 0.5 else "down"


async def snapshot(redis: Redis) -> None:
    db_ms = await _db_latency_ms()
    redis_ms = await _redis_latency_ms(redis)
    rows = [
        HealthCheck(
            module_key="database", status="ok" if db_ms is not None else "down", latency_ms=db_ms or 0
        ),
        HealthCheck(
            module_key="redis", status="ok" if redis_ms is not None else "down", latency_ms=redis_ms or 0
        ),
    ]
    if redis_ms is not None:
        alive = await scanner_alive(redis)
        rows.append(HealthCheck(module_key="scanner", status="ok" if alive else "down"))
        for check_id in CHECK_IDS:
            rate, samples = await check_error_rate(redis, check_id)
            rows.append(HealthCheck(module_key=check_id, status=_rate_status(rate, samples), error_rate=rate))
    if db_ms is None:
        return  # can't persist; the live endpoint still reports the outage
    async with db_session(DbContext.system()) as session:
        session.add_all(rows)
        await session.execute(
            delete(HealthCheck).where(HealthCheck.checked_at < datetime.now(UTC) - RETENTION)
        )


async def latest(session: AsyncSession) -> list[HealthRow]:
    stmt = (
        select(HealthCheck)
        .distinct(HealthCheck.module_key)
        .order_by(HealthCheck.module_key, HealthCheck.checked_at.desc())
    )
    return [
        HealthRow(
            module_key=h.module_key,
            status=h.status,
            error_rate=h.error_rate,
            latency_ms=h.latency_ms,
            checked_at=h.checked_at,
        )
        for h in (await session.execute(stmt)).scalars().all()
    ]
