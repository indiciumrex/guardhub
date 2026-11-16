"""Background re-proof of admin trusted domains (ADR-0003 point 3, docs/architecture.md §8.1).

`recheck_trusted_domains` re-runs the scanner's verify job for every active or suspended domain:
proof gone → `suspended`, proof back on a suspended domain → `active` (`reactivated`); each
transition is audited. At most `RECHECK_CONCURRENCY` checks run at once so the shared host and
the scanner aren't loaded. It only reads and updates trusted-domain rows: it never scans.
Registered as an Arq cron function by the jobs worker; it takes no arguments beyond `ctx`, so it
is directly callable from tests.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import Counter
from datetime import UTC, datetime

from redis.asyncio import Redis
from redis.exceptions import RedisError

from guardhub_api.admin.trusted_domains import repository
from guardhub_api.admin.trusted_domains.service import AUDIT_PREFIX, mark_failed, mark_proven
from guardhub_api.common import audit
from guardhub_api.common.redis import get_redis
from guardhub_api.config import get_settings
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.scans import queue

log = logging.getLogger("guardhub.trusted_domains")

RECHECK_CONCURRENCY = 2
ACTOR = "system:trusted-domain-recheck"
OUTCOMES = ("checked", "confirmed", "reactivated", "suspended", "still_suspended", "skipped", "errors")


async def _load_target(domain_id: uuid.UUID) -> tuple[str, str] | None:
    async with db_session(DbContext.system()) as session:
        domain = await repository.get_for_recheck(session, domain_id)
        return (domain.target_origin, domain.verification_token) if domain else None


async def _apply(domain_id: uuid.UUID, result: queue.VerifyResult) -> str:
    """Store one verify result. Returns the outcome name (see OUTCOMES)."""
    now = datetime.now(UTC)
    async with db_session(DbContext.system()) as session:
        domain = await repository.get_for_recheck(session, domain_id)
        if domain is None:  # revoked (or deleted) while we were checking: leave it alone
            return "skipped"
        if result.verified and result.method is not None:
            if mark_proven(domain, result.method, now) == "reactivated":
                await audit.record(
                    session,
                    actor=ACTOR,
                    action=f"{AUDIT_PREFIX}.reactivated",
                    target=str(domain.id),
                    metadata={"host": domain.host, "method": result.method},
                )
                return "reactivated"
            return "confirmed"
        reason = result.error or "not_found"
        if mark_failed(domain, reason, now):
            await audit.record(
                session,
                actor=ACTOR,
                action=f"{AUDIT_PREFIX}.suspended",
                target=str(domain.id),
                metadata={"host": domain.host, "reason": reason},
            )
            return "suspended"
        return "still_suspended"


async def _recheck_one(redis: Redis, domain_id: uuid.UUID, gate: asyncio.Semaphore) -> str:
    async with gate:
        target = await _load_target(domain_id)
        if target is None:
            return "skipped"
        origin, token = target
        try:
            result = await queue.request_verification(
                redis, target=origin, token=token, wait_seconds=get_settings().verify_timeout_seconds
            )
        except RedisError:
            # The queue being down says nothing about the proof: leave the domain as it is.
            log.warning("trusted_domain_recheck_queue_error", extra={"domain_id": str(domain_id)})
            return "errors"
        return await _apply(domain_id, result)


async def recheck_trusted_domains(ctx: dict[str, object]) -> dict[str, int]:
    """Re-verify every active or suspended trusted domain; returns outcome counts.

    `ctx` is the Arq job context; it is not needed (the API's own Redis client is used, so
    replies decode the same way as in the API). Pass `{}` when calling directly.
    """
    del ctx
    async with db_session(DbContext.system()) as session:
        ids = await repository.ids_to_recheck(session)
    gate = asyncio.Semaphore(RECHECK_CONCURRENCY)
    redis = get_redis()
    outcomes = await asyncio.gather(*(_recheck_one(redis, domain_id, gate) for domain_id in ids))
    counts = Counter(outcomes)
    result = {name: counts.get(name, 0) for name in OUTCOMES}
    result["checked"] = len(ids) - result["skipped"]
    log.info("trusted_domain_recheck_done", extra=result)
    return result
