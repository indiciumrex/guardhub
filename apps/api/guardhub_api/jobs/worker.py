"""Arq worker for the `api-jobs` service (docs/architecture.md §8.1). Run: `python -m guardhub_api.jobs`.

Registered work lives in two lists, one line per job:
- `FUNCTIONS`: jobs that are enqueued (`notify_scan` by api-worker after a project scan completes,
  `notify_paused` by the scheduler, `send_test_notification` by the API);
- `CRON_JOBS`: periodic jobs (`enqueue_due_scans` every 5 minutes). Cron jobs are `unique`: one
  run per tick even with several workers (e.g. two colours during a blue/green switch).
Jobs are JSON-serialised (no pickle), retries are bounded, and every job is idempotent.
"""

from __future__ import annotations

import uuid
from typing import Any  # Arq's job context is an untyped dict

from arq import Retry, cron, func
from arq.cron import CronJob
from arq.worker import Function

from guardhub_api.admin.trusted_domains.jobs import recheck_trusted_domains
from guardhub_api.alerts import notifier
from guardhub_api.common.logging import configure_logging
from guardhub_api.common.redis import close_redis, get_redis
from guardhub_api.config import get_settings
from guardhub_api.db.session import dispose_engine
from guardhub_api.jobs import client, scheduler

NOTIFY_MAX_TRIES = notifier.MAX_ATTEMPTS
NOTIFY_RETRY_BASE_SECONDS = 30
EVERY_5_MINUTES = set(range(0, 60, 5))

JobContext = dict[str, Any]


def retry_delay_seconds(job_try: int) -> int:
    """30 s, 2 min, 8 min, …: exponential backoff between alert attempts."""
    return int(NOTIFY_RETRY_BASE_SECONDS * 4 ** max(0, job_try - 1))


def _final_try(ctx: JobContext) -> bool:
    return int(ctx.get("job_try", 1)) >= NOTIFY_MAX_TRIES


def _retry(ctx: JobContext) -> Retry:
    return Retry(defer=retry_delay_seconds(int(ctx.get("job_try", 1))))


async def enqueue_due_scans(ctx: JobContext) -> dict[str, int]:
    report = await scheduler.enqueue_due_scans(get_redis())
    return report.as_log()


async def notify_scan(ctx: JobContext, scan_id: str) -> str:
    outcome = await notifier.notify_scan(uuid.UUID(scan_id), final_try=_final_try(ctx))
    if outcome == "retry":
        raise _retry(ctx)
    return outcome


async def notify_paused(ctx: JobContext, project_id: str) -> str:
    outcome = await notifier.notify_paused(
        uuid.UUID(project_id), job_id=str(ctx.get("job_id", "")), final_try=_final_try(ctx)
    )
    if outcome == "retry":
        raise _retry(ctx)
    return outcome


async def send_test_notification(ctx: JobContext, user_id: str, channel: str) -> str:
    if channel not in ("email", "slack"):
        return "not_applicable"
    return await notifier.send_test(uuid.UUID(user_id), channel, job_id=str(ctx.get("job_id", "")))


async def startup(ctx: JobContext) -> None:
    configure_logging(get_settings().log_level)


async def shutdown(ctx: JobContext) -> None:
    await client.close_arq()
    await close_redis()
    await dispose_engine()


FUNCTIONS: list[Function] = [
    func(notify_scan, max_tries=NOTIFY_MAX_TRIES, timeout=120),
    func(notify_paused, max_tries=NOTIFY_MAX_TRIES, timeout=120),
    func(send_test_notification, max_tries=1, timeout=60),
]

CRON_JOBS: list[CronJob] = [
    cron(enqueue_due_scans, minute=EVERY_5_MINUTES, second=0, unique=True, run_at_startup=False, timeout=290),
    # ADR-0003: daily background re-proof of trusted domains (suspends when the proof is gone)
    cron(
        recheck_trusted_domains,
        hour={4},
        minute={10},
        second=0,
        unique=True,
        run_at_startup=False,
        timeout=1800,
    ),
]


class WorkerSettings:
    """Read by `arq.worker.create_worker` (see guardhub_api.jobs.__main__)."""

    functions = FUNCTIONS
    cron_jobs = CRON_JOBS
    redis_settings = client.redis_settings()
    job_serializer = staticmethod(client.serialize_job)
    job_deserializer = staticmethod(client.deserialize_job)
    on_startup = startup
    on_shutdown = shutdown
    max_jobs = 4  # shared host (§7.2): alerts and scheduling are light, keep concurrency small
    job_timeout = 300
    keep_result = 3600
    health_check_interval = 60
