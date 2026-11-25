"""Anonymous free scan (§8.7) with ownership proof (§9.2, ADR-0001).

Flow: create challenge → visitor publishes the token → verify + queue the scan → the visitor
reads the result with a one-time access token. Only a keyed hash of the token is stored, and
RLS shows the scan only to a request that presents that token. Rate-limited per IP and per target.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel
from redis.asyncio import Redis

from guardhub_api.common import audit, ratelimit
from guardhub_api.common.crypto import keyed_hash, random_token
from guardhub_api.common.errors import NotFoundError
from guardhub_api.common.urls import normalize_origin
from guardhub_api.config import get_settings
from guardhub_api.db.models import TargetVerification
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.platform import service as platform
from guardhub_api.projects import repository as project_repo
from guardhub_api.projects.verification import (
    VerificationInstructions,
    instructions,
    new_token,
    prove_ownership,
)
from guardhub_api.scans import repository as scan_repo
from guardhub_api.scans import service as scan_service
from guardhub_api.scans.schemas import ScanView


class ChallengeView(BaseModel):
    challenge_id: uuid.UUID
    target_origin: str
    token: str
    expires_at: datetime
    instructions: VerificationInstructions


class StartedScan(BaseModel):
    scan_id: uuid.UUID
    access_token: str


def _pepper() -> str:
    return get_settings().hash_pepper.get_secret_value()


async def create_challenge(redis: Redis, *, target_url: str, ip: str) -> ChallengeView:
    settings = get_settings()
    ip_hash = keyed_hash(_pepper(), ip)
    await platform.require_no_maintenance()
    await platform.require_feature("flags.public_scan")
    limit = await platform.int_value("rate.challenge_per_ip_hour")
    await ratelimit.enforce(redis, "challenge-ip", ip_hash, limit=limit, window=3600)
    origin = normalize_origin(target_url, allow_private_hosts=settings.private_host_allowlist)
    token = new_token()
    async with db_session(DbContext.system()) as session:
        challenge = await project_repo.add_challenge(
            session,
            TargetVerification(
                user_id=None,
                target_origin=origin,
                token=token,
                requester_ip_hash=ip_hash,
                expires_at=datetime.now(UTC) + timedelta(hours=settings.challenge_ttl_hours),
            ),
        )
    return ChallengeView(
        challenge_id=challenge.id,
        target_origin=origin,
        token=token,
        expires_at=challenge.expires_at,
        instructions=instructions(origin, token),
    )


async def verify_and_scan(redis: Redis, *, challenge_id: uuid.UUID, ip: str) -> StartedScan:
    ip_hash = keyed_hash(_pepper(), ip)
    async with db_session(DbContext.system()) as session:
        challenge = await project_repo.get_challenge(session, challenge_id)
        if challenge is None or challenge.user_id is not None or challenge.expires_at < datetime.now(UTC):
            raise NotFoundError("challenge_not_found", "This verification has expired. Start again.")
        origin, token = challenge.target_origin, challenge.token
    await platform.require_no_maintenance()
    await platform.require_feature("flags.public_scan")
    per_ip = await platform.int_value("rate.anon_scan_per_ip_hour")
    per_target = await platform.int_value("rate.anon_scan_per_target_hour")
    await ratelimit.enforce(redis, "anon-scan-ip", ip_hash, limit=per_ip, window=3600)
    await ratelimit.enforce(
        redis, "anon-scan-target", keyed_hash(_pepper(), origin), limit=per_target, window=3600
    )

    # Ownership is re-proven for every anonymous scan: the proof must be live right now.
    method = await prove_ownership(redis, origin=origin, token=token)
    access_token = random_token("ghs", 32)
    token_hash = keyed_hash(_pepper(), access_token)
    async with db_session(DbContext.system()) as session:
        challenge = await project_repo.get_challenge(session, challenge_id)
        if challenge is None:
            raise NotFoundError("challenge_not_found", "This verification has expired. Start again.")
        challenge.verified_at = datetime.now(UTC)
        challenge.method = method
        await audit.record(
            session, actor="anonymous", action="target.verified", target=origin, metadata={"method": method}
        )
    scan = await scan_service.create_and_enqueue(
        redis,
        target=origin,
        project_id=None,
        user_id=None,
        verification_id=challenge_id,
        public_token_hash=token_hash,
        ctx=DbContext.system(),
    )
    async with db_session(DbContext.system()) as session:
        await audit.record(session, actor="anonymous", action="scan.create", target=str(scan.id))
    return StartedScan(scan_id=scan.id, access_token=access_token)


async def get_public_scan(redis: Redis, *, scan_id: uuid.UUID, access_token: str, locale: str) -> ScanView:
    token_hash = keyed_hash(_pepper(), access_token)
    async with db_session(DbContext.anon(token_hash)) as session:
        scan = await scan_repo.get(session, scan_id)  # RLS: only visible with the matching token
        if scan is None:
            raise NotFoundError("scan_not_found", "Scan not found.")
        return await scan_service.build_view(session, redis, scan, locale)
