"""Redis wire protocol to the Go scanner (docs/architecture.md §2, ADR-0002).

Publishes scan/verify jobs to `gh:jobs`, waits for verify replies, and reads live progress
hashes. Payloads are versioned JSON (`"v": 1`).
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass

from redis.asyncio import Redis

JOBS_STREAM = "gh:jobs"
EVENTS_STREAM = "gh:events"
SCANNER_GROUP = "gh-scanners"
API_GROUP = "gh-api"
STREAM_MAXLEN = 10_000
# A blocking BLPOP must return well inside the client's socket_timeout (10 s, common/redis.py),
# or the socket read times out first and a slow-but-fine verification looks like an outage.
BLPOP_SLICE_SECONDS = 5.0


def progress_key(scan_id: uuid.UUID | str) -> str:
    return f"gh:scan:{scan_id}:progress"


@dataclass(frozen=True, slots=True)
class VerifyResult:
    verified: bool
    method: str | None
    error: str | None


async def enqueue_scan(
    redis: Redis, *, scan_id: uuid.UUID, target: str, checks: list[str], deadline_seconds: int
) -> str:
    payload = {
        "v": 1,
        "kind": "scan",
        "job_id": str(uuid.uuid4()),
        "scan_id": str(scan_id),
        "target": target,
        "checks": checks,
        "deadline_seconds": deadline_seconds,
    }
    msg_id = await redis.xadd(
        JOBS_STREAM, {"payload": json.dumps(payload)}, maxlen=STREAM_MAXLEN, approximate=True
    )
    return str(msg_id)


REPO_TOKEN_PREFIX = "gh:repo-token:"  # noqa: S105 (a Redis key prefix, not a secret)
REPO_TOKEN_TTL_SECONDS = 600


async def enqueue_repo_scan(
    redis: Redis, *, scan_id: uuid.UUID, repo: str, token: str, checks: list[str], deadline_seconds: int
) -> str:
    """Queue a repository scan (ADR-0006). The narrowed installation token goes under a one-time
    key the scanner reads with GETDEL (10-minute TTL); the job stream only names that key."""
    job_id = str(uuid.uuid4())
    token_key = REPO_TOKEN_PREFIX + job_id
    await redis.set(token_key, token, ex=REPO_TOKEN_TTL_SECONDS)
    payload = {
        "v": 1,
        "kind": "repo_scan",
        "job_id": job_id,
        "scan_id": str(scan_id),
        "repo": repo,
        "token_key": token_key,
        "checks": checks,
        "deadline_seconds": deadline_seconds,
    }
    try:
        msg_id = await redis.xadd(
            JOBS_STREAM, {"payload": json.dumps(payload)}, maxlen=STREAM_MAXLEN, approximate=True
        )
    except Exception:
        await redis.delete(token_key)
        raise
    return str(msg_id)


async def request_verification(redis: Redis, *, target: str, token: str, wait_seconds: float) -> VerifyResult:
    """Ask the scanner (the single hardened egress client) to check an ownership proof."""
    job_id = str(uuid.uuid4())
    reply_key = f"gh:verify-reply:{job_id}"
    payload = {
        "v": 1,
        "kind": "verify",
        "job_id": job_id,
        "target": target,
        "token": token,
        "reply_key": reply_key,
    }
    await redis.xadd(JOBS_STREAM, {"payload": json.dumps(payload)}, maxlen=STREAM_MAXLEN, approximate=True)
    deadline = time.monotonic() + wait_seconds
    reply = None
    while reply is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        reply = await redis.blpop([reply_key], timeout=min(remaining, BLPOP_SLICE_SECONDS))
    if reply is None:
        return VerifyResult(verified=False, method=None, error="timeout")
    await redis.delete(reply_key)
    try:
        data = json.loads(reply[1])
    except (json.JSONDecodeError, TypeError):
        return VerifyResult(verified=False, method=None, error="internal")
    if not isinstance(data, dict) or data.get("job_id") != job_id:
        return VerifyResult(verified=False, method=None, error="internal")
    method = data.get("method")
    allowed_methods = {"well_known", "meta_tag", "dns_txt"}
    return VerifyResult(
        verified=data.get("verified") is True and method in allowed_methods,
        method=method if method in allowed_methods else None,
        error=data.get("error") if isinstance(data.get("error"), str) else None,
    )


async def read_progress(redis: Redis, scan_id: uuid.UUID) -> dict[str, str]:
    raw = await redis.hgetall(progress_key(scan_id))
    return {str(k): str(v) for k, v in raw.items()}


async def scanner_alive(redis: Redis, max_idle_ms: int = 30_000) -> bool | None:
    """True if a scanner consumer read from the jobs stream recently; None if unknown."""
    try:
        consumers = await redis.xinfo_consumers(JOBS_STREAM, SCANNER_GROUP)
    except Exception:
        return None
    return any(int(c.get("idle", max_idle_ms + 1)) <= max_idle_ms for c in consumers)
