"""Enqueue side of the Arq background jobs (docs/architecture.md §8.1, ADR-0002).

api and api-worker only ENQUEUE here; `api-jobs` (guardhub_api.jobs.worker) runs the jobs.
Jobs are serialised as JSON instead of Arq's default pickle, so nothing that can write to Redis
can make a worker unpickle arbitrary objects. Job ids are deterministic where a job must not run
twice for the same thing (e.g. one alert job per scan).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any  # JSON job payloads (Arq's serializer contract)

from arq.connections import ArqRedis, RedisSettings, create_pool

from guardhub_api.config import get_settings

# Function names registered in guardhub_api.jobs.worker (kept here so producers never import jobs code).
NOTIFY_SCAN = "notify_scan"
NOTIFY_PAUSED = "notify_paused"
SEND_TEST_NOTIFICATION = "send_test_notification"

_pool: ArqRedis | None = None


def serialize_job(data: dict[str, Any]) -> bytes:
    return json.dumps(data, separators=(",", ":"), default=str).encode("utf-8")


def deserialize_job(raw: bytes) -> dict[str, Any]:
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("job payload must be a JSON object")
    return data


def redis_settings() -> RedisSettings:
    settings = RedisSettings.from_dsn(get_settings().redis_url.get_secret_value())
    settings.conn_timeout = 5
    settings.conn_retries = 3
    return settings


async def get_arq() -> ArqRedis:
    global _pool  # noqa: PLW0603 — process-wide pool
    if _pool is None:
        _pool = await create_pool(
            redis_settings(), job_serializer=serialize_job, job_deserializer=deserialize_job
        )
    return _pool


def set_arq(pool: ArqRedis | None) -> None:
    """Override the pool (tests)."""
    global _pool  # noqa: PLW0603
    _pool = pool


async def close_arq() -> None:
    global _pool  # noqa: PLW0603
    if _pool is not None:
        await _pool.aclose()
        _pool = None


async def enqueue_notify_scan(scan_id: uuid.UUID) -> bool:
    """Queue the change alert for a completed project scan. False if it is already queued/done."""
    job = await (await get_arq()).enqueue_job(NOTIFY_SCAN, str(scan_id), _job_id=f"notify-scan:{scan_id}")
    return job is not None


async def enqueue_notify_paused(project_id: uuid.UUID, paused_at: datetime) -> bool:
    """Queue the "monitoring paused" alert. One job per pause (the pause time is part of the id)."""
    stamp = int(paused_at.timestamp())
    job = await (await get_arq()).enqueue_job(
        NOTIFY_PAUSED, str(project_id), _job_id=f"notify-paused:{project_id}:{stamp}"
    )
    return job is not None


async def enqueue_test_notification(user_id: uuid.UUID, channel: str) -> None:
    await (await get_arq()).enqueue_job(SEND_TEST_NOTIFICATION, str(user_id), channel)
