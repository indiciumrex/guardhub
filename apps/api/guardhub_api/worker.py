"""Background worker: ingests scanner events, reaps stuck scans, and records health snapshots.

Run with `python -m guardhub_api.worker`. Several replicas are safe: the Redis consumer group
shares events between them, and every handler is idempotent.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal
import socket
from datetime import UTC, datetime, timedelta
from typing import cast

from redis.asyncio import Redis
from redis.exceptions import RedisError, ResponseError

from guardhub_api.common.logging import configure_logging
from guardhub_api.common.observability import init_observability
from guardhub_api.common.redis import close_redis, get_redis
from guardhub_api.config import get_settings
from guardhub_api.db.session import DbContext, db_session, dispose_engine
from guardhub_api.health import service as health
from guardhub_api.jobs.client import close_arq
from guardhub_api.scans import repository as scan_repo
from guardhub_api.scans.ingest import decode_payload, handle_event
from guardhub_api.scans.queue import API_GROUP, EVENTS_STREAM

log = logging.getLogger("guardhub.worker")

MAX_ATTEMPTS = 5
RECLAIM_IDLE_MS = 60_000
HEALTH_INTERVAL_S = 60
REAPER_GRACE = timedelta(minutes=2)

# redis-py returns loosely typed stream replies; with decode_responses=True they are str-keyed.
StreamMessages = list[tuple[str, dict[str, str]]]


async def ensure_group(redis: Redis) -> None:
    try:
        await redis.xgroup_create(EVENTS_STREAM, API_GROUP, id="0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def process_message(redis: Redis, msg_id: str, fields: dict[str, str]) -> None:
    event = decode_payload(fields)
    if event is None:
        log.warning("malformed_event_acked", extra={"msg_id": msg_id})
        await redis.xack(EVENTS_STREAM, API_GROUP, msg_id)
        return
    attempts_key = f"gh:events:attempts:{msg_id}"
    try:
        await handle_event(redis, event)
    except Exception:
        attempts = int(await redis.incr(attempts_key))
        await redis.expire(attempts_key, 3600)
        log.exception("event_processing_failed", extra={"msg_id": msg_id, "attempt": attempts})
        if attempts < MAX_ATTEMPTS:
            return  # left pending → reclaimed and retried later
        log.error("event_dead_lettered", extra={"msg_id": msg_id})
        await redis.rpush("gh:events:dead", fields.get("payload", ""))
    await redis.xack(EVENTS_STREAM, API_GROUP, msg_id)
    await redis.delete(attempts_key)


async def consume_once(redis: Redis, consumer: str, block_ms: int = 5000) -> int:
    """Process one batch (new messages plus reclaimed stuck ones). Returns the messages handled."""
    handled = 0
    claim_result = await redis.xautoclaim(
        EVENTS_STREAM, API_GROUP, consumer, min_idle_time=RECLAIM_IDLE_MS, start_id="0-0", count=10
    )
    claimed = cast(StreamMessages, claim_result[1])
    for msg_id, fields in claimed:
        if fields:
            await process_message(redis, msg_id, fields)
            handled += 1
    batches = cast(
        list[tuple[str, StreamMessages]] | None,
        await redis.xreadgroup(API_GROUP, consumer, {EVENTS_STREAM: ">"}, count=10, block=block_ms),
    )
    for _stream, messages in batches or []:
        for msg_id, fields in messages:
            await process_message(redis, msg_id, fields)
            handled += 1
    return handled


async def reap_stuck_scans() -> int:
    """Fail scans that outlived their deadline (e.g. scanner crashed) so users never wait forever."""
    cutoff = datetime.now(UTC) - timedelta(seconds=get_settings().scan_deadline_seconds) - REAPER_GRACE
    async with db_session(DbContext.system()) as session:
        count = await scan_repo.fail_stuck(session, cutoff, datetime.now(UTC))
    if count:
        log.warning("reaped_stuck_scans", extra={"count": count})
    return count


async def run(stop: asyncio.Event) -> None:
    redis = get_redis()
    consumer = f"{socket.gethostname()}-{os.getpid()}"
    await ensure_group(redis)
    log.info("worker_started", extra={"consumer": consumer})
    next_periodic = 0.0
    loop = asyncio.get_running_loop()
    while not stop.is_set():
        try:
            await consume_once(redis, consumer)
            if loop.time() >= next_periodic:
                next_periodic = loop.time() + HEALTH_INTERVAL_S
                await reap_stuck_scans()
                await health.snapshot(redis)
        except (RedisError, OSError):
            log.exception("worker_loop_error")
            await asyncio.sleep(2)


async def _main() -> None:
    configure_logging(get_settings().log_level)
    init_observability("api-worker")  # no-op unless SENTRY_DSN is set
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):  # Windows dev shells
            loop.add_signal_handler(sig, stop.set)
    try:
        await run(stop)
    finally:
        await close_arq()
        await close_redis()
        await dispose_engine()


if __name__ == "__main__":
    asyncio.run(_main())
