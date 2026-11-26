"""Session registry (Admin Panel, Prompt 2 §5): which full (2FA) sessions an account has, so an
admin can see and end them. Sessions stay stateless JWTs; this is a Redis hash per user
(`gh:sessions:<user id>`: jti -> issued, expires, keyed IP hash, short client label), pruned on
read. Ending a session uses the existing per-jti revocation (auth/service.revoke_jti).
"""

from __future__ import annotations

import json
import logging
import time
import uuid

from pydantic import BaseModel
from redis.asyncio import Redis

from guardhub_api.auth.security import SessionClaims

log = logging.getLogger(__name__)
PREFIX = "gh:sessions:"
REVOKED = "gh:session:revoked:"


class SessionView(BaseModel):
    jti: str
    issued_at: int
    expires_at: int
    ip_hash: str
    client: str


def client_label(user_agent: str) -> str:
    """A coarse, non-identifying label of the browser and OS (never the full user agent)."""
    ua = user_agent.lower()
    browser = next(
        (
            b
            for k, b in (
                ("edg/", "Edge"),
                ("firefox/", "Firefox"),
                ("chrome/", "Chrome"),
                ("safari/", "Safari"),
            )
            if k in ua
        ),
        "Other",
    )
    system = next(
        (
            s
            for k, s in (
                ("windows", "Windows"),
                ("android", "Android"),
                ("iphone", "iOS"),
                ("mac os", "macOS"),
                ("linux", "Linux"),
            )
            if k in ua
        ),
        "",
    )
    return f"{browser} · {system}" if system else browser


async def record(redis: Redis, claims: SessionClaims, *, ip_hash: str, user_agent: str) -> None:
    entry = {
        "iat": int(time.time()),
        "exp": claims.exp,
        "ip": ip_hash[:16],
        "client": client_label(user_agent),
    }
    key = f"{PREFIX}{claims.user_id}"
    try:
        await redis.hset(key, claims.jti, json.dumps(entry))
        want = max(60, claims.exp - int(time.time()))
        if await redis.ttl(key) < want:  # the hash lives as long as its longest session
            await redis.expire(key, want)
    except Exception:
        log.warning("session_record_failed")


async def forget(redis: Redis, user_id: uuid.UUID, jti: str) -> None:
    try:
        await redis.hdel(f"{PREFIX}{user_id}", jti)
    except Exception:
        log.warning("session_forget_failed")


async def list_sessions(redis: Redis, user_id: uuid.UUID) -> list[SessionView]:
    key = f"{PREFIX}{user_id}"
    now = int(time.time())
    out: list[SessionView] = []
    stale: list[str] = []
    for raw_jti, raw in (await redis.hgetall(key)).items():
        jti = raw_jti.decode() if isinstance(raw_jti, bytes) else str(raw_jti)
        try:
            e = json.loads(raw)
        except ValueError:
            stale.append(jti)
            continue
        if int(e.get("exp", 0)) <= now or await redis.exists(f"{REVOKED}{jti}"):
            stale.append(jti)
            continue
        out.append(
            SessionView(
                jti=jti,
                issued_at=int(e["iat"]),
                expires_at=int(e["exp"]),
                ip_hash=str(e.get("ip", "")),
                client=str(e.get("client", "")),
            )
        )
    if stale:
        await redis.hdel(key, *stale)
    return sorted(out, key=lambda s: -s.issued_at)


async def end(redis: Redis, user_id: uuid.UUID, jti: str | None = None) -> int:
    """End one session (jti) or all of them. Returns how many were ended."""
    ended = 0
    for s in await list_sessions(redis, user_id):
        if jti is None or s.jti == jti:
            await redis.set(f"{REVOKED}{s.jti}", "1", ex=max(1, s.expires_at - int(time.time())))
            await redis.hdel(f"{PREFIX}{user_id}", s.jti)
            ended += 1
    return ended


async def end_others(redis: Redis, user_id: uuid.UUID, *, keep: str) -> int:
    """End every session of the account except `keep` (the one making the request)."""
    ended = 0
    for s in await list_sessions(redis, user_id):
        if s.jti != keep:
            await redis.set(f"{REVOKED}{s.jti}", "1", ex=max(1, s.expires_at - int(time.time())))
            await redis.hdel(f"{PREFIX}{user_id}", s.jti)
            ended += 1
    return ended
