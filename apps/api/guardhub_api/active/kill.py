"""The active-test kill switch (ADR-0008 §3), set from the admin.

The scanner refuses every active request while gh:active:kill (all scans) or
gh:active:kill:<scan_id> (one scan) exists, re-reading it at most once a second, and treats an
unreadable switch as set (fail closed). Setting it is immediate; clearing it lets new requests
through again, but a scan that already stopped stays stopped. Every change is audited.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel
from redis.asyncio import Redis

GLOBAL_KEY = "gh:active:kill"


def key_for(scan_id: uuid.UUID | None) -> str:
    return GLOBAL_KEY if scan_id is None else f"{GLOBAL_KEY}:{scan_id}"


class KillState(BaseModel):
    scope: str  # "global" or the scan id
    engaged: bool


async def state(redis: Redis, scan_id: uuid.UUID | None = None) -> KillState:
    engaged = bool(await redis.exists(key_for(scan_id)))
    return KillState(scope="global" if scan_id is None else str(scan_id), engaged=engaged)


async def engage(redis: Redis, scan_id: uuid.UUID | None = None) -> None:
    """Stop first: called before the audit row is written (stopping never waits on the DB)."""
    await redis.set(key_for(scan_id), "1")


async def release(redis: Redis, scan_id: uuid.UUID | None = None) -> None:
    """Called only after the audit row of the release has been committed."""
    await redis.delete(key_for(scan_id))
