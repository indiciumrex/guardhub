"""Owner-target active scans (ADR-0008 §8, founder 2026-11-25): an admin runs active checks on a
domain GuardHub itself owns and has proven (an admin trusted domain, ADR-0003). Customer targets
have no path here; they need the consent UI, ToS and OOB first.

Nothing is queued unless ALL of these hold, checked in this order, every time:

1. the founder's approval: API setting ACTIVE_TESTING_APPROVED;
2. every requested module switched on (and not in maintenance); active_ssrf only when a scanner
   reports an OOB collaborator;
3. the kill switch released (unreadable counts as engaged: fail closed);
4. a scanner reporting SCANNER_ACTIVE_ENABLED=true (the scanner refuses the job anyway when off);
5. the target is an `active` admin trusted domain (proven, not suspended or revoked); the scanner
   proves ownership again at scan start with its token;
6. no other active scan of that origin is running (one per origin: a Redis lock, released when
   the scan ends (scans/ingest.py) and expiring after the longest active deadline anyway).

The admin's go is recorded as an `active_consents` row (consent version OWNER_CONSENT_VERSION,
the SHA-256 of OWNER_STATEMENT) and in the audit log (active.scan.started).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import uuid
from typing import Literal

from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy import select

from guardhub_api.active import kill
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit
from guardhub_api.common.errors import ConflictError, NotFoundError, UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.db.models import ActiveConsent, AdminTrustedDomain, Module, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.contract_gen import ACTIVE_CHECK_IDS
from guardhub_api.scans.queue import JOBS_STREAM, STREAM_MAXLEN

SCANNER_INFO_PREFIX = "gh:scanner:info:"
ORIGIN_LOCK_PREFIX = "gh:active:origin-lock:"
SESSIONS_PREFIX = "gh:active-sessions:"  # the scanner's ActiveSessionPrefix (read with GETDEL)
SESSIONS_TTL_SECONDS = 900
ACTIVE_DEADLINE_SECONDS = 600  # the scanner's default active deadline (max 15 min)
ORIGIN_LOCK_SECONDS = 15 * 60 + 60  # the longest active deadline, plus a minute
MAX_EXCLUDED_PATHS = 20

OWNER_CONSENT_VERSION = "owner-internal-v1"
OWNER_STATEMENT = (
    "GuardHub owns and controls this origin (proven as an admin trusted domain, ownership proven "
    "again at scan start). The founder approved active testing of GuardHub-owned targets after the "
    "live scope-guard and kill-switch proof (2026-11-25). GET only, 1 request/s, 300 requests per "
    "scan, reviewed payloads only (ADR-0008)."
)
OWNER_STATEMENT_SHA256 = hashlib.sha256(OWNER_STATEMENT.encode()).hexdigest()


class TestAccount(BaseModel):
    """One of two test accounts for IDOR (ADR-0008 §5). Kept only in a one-time Redis key that the
    scanner reads and deletes at scan start; never stored, logged or returned."""

    cookie: str = Field(min_length=1, max_length=4096)
    marker: str = Field(min_length=6, max_length=256)


class OwnerScanRequest(BaseModel):
    trusted_domain_id: uuid.UUID
    checks: list[str] = Field(min_length=1, max_length=len(ACTIVE_CHECK_IDS))
    exclude: list[str] = Field(default_factory=list, max_length=MAX_EXCLUDED_PATHS)
    account_a: TestAccount | None = None
    account_b: TestAccount | None = None


class OwnerScanStarted(BaseModel):
    scan_id: uuid.UUID
    consent_id: uuid.UUID
    origin: str
    checks: list[str]
    exclude: list[str]
    idor_accounts: bool


Lock = Literal["approval", "modules", "kill_switch", "scanner_switch", "target", "origin_busy"]


class OwnerScanReadiness(BaseModel):
    """What stands between the admin and an owner-target active scan (read-only)."""

    approved: bool
    modules_on: list[str]
    oob_configured: bool
    kill_engaged: bool
    scanner_switch: Literal["on", "off", "unknown"]
    targets: list[dict[str, str]]  # active trusted domains: id, host, origin
    blocked_by: list[Lock]


def _refuse(code: str, message: str) -> UnprocessableError:
    return UnprocessableError(code, message)


def _valid_exclude(paths: list[str]) -> list[str]:
    out: list[str] = []
    for raw in paths:
        p = raw.strip()
        if not p.startswith("/") or len(p) > 512 or any(c in p for c in "\r\n?#"):
            raise _refuse("invalid_excluded_path", f"Excluded paths start with / and carry no query: {p!r}")
        if p not in out:
            out.append(p)
    return out


async def _scanner_state(redis: Redis) -> tuple[Literal["on", "off", "unknown"], bool]:
    try:
        keys = [k async for k in redis.scan_iter(match=SCANNER_INFO_PREFIX + "*", count=100)][:50]
        values = await redis.mget(keys) if keys else []
    except Exception:
        return "unknown", False
    infos: list[dict[str, object]] = []
    for raw in values:
        if not raw:
            continue
        try:
            info = json.loads(raw)
        except ValueError:
            continue
        if isinstance(info, dict):
            infos.append(info)
    if not infos:
        return "unknown", False
    switch: Literal["on", "off"] = "on" if any(i.get("active_enabled") is True for i in infos) else "off"
    return switch, any(i.get("active_oob") is True for i in infos)


async def _kill_engaged(redis: Redis) -> bool:
    try:
        return (await kill.state(redis, None)).engaged
    except Exception:
        return True  # unreadable means killed (ADR-0008 §3)


async def readiness(claims: SessionClaims, redis: Redis) -> OwnerScanReadiness:
    async with db_session(DbContext(role="admin", user_id=claims.user_id)) as session:
        modules_on = sorted(
            (
                await session.execute(
                    select(Module.key).where(
                        Module.key.in_(ACTIVE_CHECK_IDS),
                        Module.enabled_global.is_(True),
                        Module.maintenance.is_(False),
                    )
                )
            ).scalars()
        )
        domains = (
            (
                await session.execute(
                    select(AdminTrustedDomain)
                    .where(AdminTrustedDomain.status == "active")
                    .order_by(AdminTrustedDomain.host)
                )
            )
            .scalars()
            .all()
        )
    switch, oob = await _scanner_state(redis)
    killed = await _kill_engaged(redis)
    approved = get_settings().active_testing_approved
    blocked: list[Lock] = []
    if not approved:
        blocked.append("approval")
    if not modules_on:
        blocked.append("modules")
    if killed:
        blocked.append("kill_switch")
    if switch != "on":
        blocked.append("scanner_switch")
    if not domains:
        blocked.append("target")
    return OwnerScanReadiness(
        approved=approved,
        modules_on=modules_on,
        oob_configured=oob,
        kill_engaged=killed,
        scanner_switch=switch,
        targets=[{"id": str(d.id), "host": d.host, "origin": d.target_origin} for d in domains],
        blocked_by=blocked,
    )


async def _checked(claims: SessionClaims, redis: Redis, req: OwnerScanRequest) -> AdminTrustedDomain:
    """Locks 1-5 (module docstring), in order; raises on the first that does not allow the scan."""
    unknown = [c for c in req.checks if c not in ACTIVE_CHECK_IDS]
    if unknown:
        raise _refuse("not_an_active_check", f"Not active checks: {', '.join(unknown)}")
    if (req.account_a is None) != (req.account_b is None):
        raise _refuse("idor_needs_two_accounts", "IDOR needs both test accounts, or neither.")
    if not get_settings().active_testing_approved:  # 1. the founder's approval
        raise _refuse("active_testing_not_approved", "Active testing is not approved (founder checkpoint).")
    async with db_session(DbContext(role="admin", user_id=claims.user_id)) as session:
        on = set(
            (
                await session.execute(
                    select(Module.key).where(
                        Module.key.in_(req.checks),
                        Module.enabled_global.is_(True),
                        Module.maintenance.is_(False),
                    )
                )
            ).scalars()
        )
        domain = await session.get(AdminTrustedDomain, req.trusted_domain_id)
    off = [c for c in req.checks if c not in on]
    if off:  # 2. every requested module on
        raise _refuse("active_module_off", f"Switched off or in maintenance: {', '.join(off)}")
    switch, oob = await _scanner_state(redis)
    if "active_ssrf" in req.checks and not oob:
        raise _refuse("oob_not_configured", "active_ssrf needs the OOB collaborator (not configured).")
    if await _kill_engaged(redis):  # 3. the kill switch
        raise _refuse("active_killed", "The active-test kill switch is engaged.")
    if switch != "on":  # 4. the scanner switch
        raise _refuse("scanner_active_disabled", "No scanner runs with SCANNER_ACTIVE_ENABLED=true.")
    if domain is None or domain.status != "active":  # 5. an owned, proven target only
        raise NotFoundError("trusted_domain_not_active", "Not an active (proven) admin trusted domain.")
    return domain


async def start(claims: SessionClaims, redis: Redis, req: OwnerScanRequest) -> OwnerScanStarted:
    req = req.model_copy(update={"checks": sorted(set(req.checks)), "exclude": _valid_exclude(req.exclude)})
    domain = await _checked(claims, redis, req)
    origin = domain.target_origin
    scan_id = uuid.uuid4()
    # 6. one active scan per origin
    if not await redis.set(ORIGIN_LOCK_PREFIX + origin, str(scan_id), nx=True, ex=ORIGIN_LOCK_SECONDS):
        raise ConflictError("active_scan_running", "An active scan of this origin is already running.")
    queued = False
    try:
        consent_id = await _record(claims, req, domain, scan_id)
        await _enqueue(redis, req, domain, scan_id, consent_id)
        queued = True
    finally:
        if not queued:
            await redis.delete(ORIGIN_LOCK_PREFIX + origin)
            async with db_session(DbContext.system()) as session:
                scan = await session.get(Scan, scan_id)
                if scan is not None and scan.status == "queued":
                    scan.status, scan.error = "failed", "internal"
    return OwnerScanStarted(
        scan_id=scan_id,
        consent_id=consent_id,
        origin=origin,
        checks=req.checks,
        exclude=req.exclude,
        idor_accounts=req.account_a is not None,
    )


async def _record(
    claims: SessionClaims, req: OwnerScanRequest, domain: AdminTrustedDomain, scan_id: uuid.UUID
) -> uuid.UUID:
    """The consent row, the scan row and the audit row, in one transaction."""
    consent_id = uuid.uuid4()
    origin = domain.target_origin
    async with db_session(DbContext.system()) as session:
        session.add(
            ActiveConsent(
                id=consent_id,
                user_id=claims.user_id,
                origin=origin,
                excluded_paths=req.exclude,
                checks=req.checks,
                consent_version=OWNER_CONSENT_VERSION,
                consent_sha256=OWNER_STATEMENT_SHA256,
            )
        )
        # no project: the scans table needs a public token hash instead; this one's token is never
        # given out (secrets.token_bytes), so only admins see the scan
        unseen = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        scan = Scan(id=scan_id, user_id=claims.user_id, target_url=origin, checks=req.checks)
        scan.public_token_hash = unseen
        session.add(scan)
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="active.scan.started",
            target=str(scan_id),
            metadata={
                "origin": origin,
                "checks": ",".join(req.checks),
                "exclude": ",".join(req.exclude),
                "consent_id": str(consent_id),
                "trusted_domain_id": str(domain.id),
                "idor_accounts": str(req.account_a is not None).lower(),
            },
        )
    return consent_id


async def _enqueue(
    redis: Redis, req: OwnerScanRequest, domain: AdminTrustedDomain, scan_id: uuid.UUID, consent_id: uuid.UUID
) -> None:
    job_id = str(uuid.uuid4())
    session_key = ""
    if req.account_a is not None and req.account_b is not None:
        session_key = SESSIONS_PREFIX + job_id
        accounts = {
            "a": {"name": "A", "cookie": req.account_a.cookie, "marker": req.account_a.marker},
            "b": {"name": "B", "cookie": req.account_b.cookie, "marker": req.account_b.marker},
        }
        await redis.set(session_key, json.dumps(accounts), ex=SESSIONS_TTL_SECONDS)
    payload = {
        "v": 1,
        "kind": "active_scan",
        "job_id": job_id,
        "scan_id": str(scan_id),
        "target": domain.target_origin,
        "checks": req.checks,
        "deadline_seconds": ACTIVE_DEADLINE_SECONDS,
        "token": domain.verification_token,
        "consent_id": str(consent_id),
        "exclude": req.exclude,
        "session_key": session_key,
    }
    await redis.xadd(JOBS_STREAM, {"payload": json.dumps(payload)}, maxlen=STREAM_MAXLEN, approximate=True)


async def release_origin_lock(redis: Redis, origin: str, scan_id: uuid.UUID) -> None:
    """Called when an active scan ends: frees its origin, only if the lock is still this scan's."""
    key = ORIGIN_LOCK_PREFIX + origin
    if await redis.get(key) in (str(scan_id), str(scan_id).encode()):
        await redis.delete(key)
