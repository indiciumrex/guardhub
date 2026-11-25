"""Daily retention purge of the active request log (ADR-0008 §7: 30 days, founder 2026-11-25).

Registered as an Arq cron function by the jobs worker (one run per day across workers and
colours). The purge and its audit record share one transaction: a purge that removed rows is
always audited, and a failed purge removes nothing.
"""

from __future__ import annotations

import logging
from typing import Any

from guardhub_api.active import log as active_log
from guardhub_api.common import audit
from guardhub_api.db.session import DbContext, db_session

log = logging.getLogger("guardhub.active")


async def purge_active_request_log(ctx: dict[str, Any] | None = None) -> int:
    async with db_session(DbContext.system()) as session:
        removed = await active_log.purge_expired(session)
        if removed:
            await audit.record(
                session,
                actor=active_log.PURGE_ACTOR,
                action="active_request_log.purged",
                metadata={"rows": str(removed), "retention_days": str(active_log.RETENTION_DAYS)},
            )
    log.info("active_request_log_purged", extra={"rows": str(removed)})
    return removed
