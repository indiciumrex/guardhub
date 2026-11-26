"""Active tests on a CUSTOMER's own site (Phase 5B). Built, and OFF: nothing is queued unless every
lock holds, in this order, every time:

Go-live (the founder's human gate, all three):
 1. the founder's go:           CUSTOMER_ACTIVE_TESTING_GO=true;
 2. final, published terms:     ACTIVE_TOS_VERSION and ACTIVE_TOS_SHA256 set (empty = draft);
 3. a live OOB collaborator:    a scanner reports active_oob (every module, not only SSRF);
The owner-target locks, unchanged:
 4. the founder's approval:     ACTIVE_TESTING_APPROVED;
 5. every requested module switched on (not in maintenance);
 6. the kill switch released (unreadable = engaged);
 7. a scanner with SCANNER_ACTIVE_ENABLED=true;
The customer and the site:
 8. the customer's own site project, with a fresh ownership proof (§9.2, re-proven if stale; the
    scanner proves it again at scan start with the project's token);
 9. the customer accepts exactly the current terms version for this scan (an active_consents
    row with the version and the terms' SHA-256);
10. one active scan per site at a time (origin lock).
The three operating preconditions: one active scan per site (10), the request log deleted after
30 days (migration 0018, daily purge), and the customer's own "stop" for a running scan (the
per-scan kill key, honoured by the scanner within a second).
IDOR (needs test-account cookies) is not offered to customers in this version.
"""

from __future__ import annotations

import json
import uuid
from typing import Literal

from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy import select

from guardhub_api.active import kill
from guardhub_api.active.owner_scan import (
    ACTIVE_DEADLINE_SECONDS,
    MAX_EXCLUDED_PATHS,
    ORIGIN_LOCK_PREFIX,
    ORIGIN_LOCK_SECONDS,
    _kill_engaged,
    _scanner_state,
    _valid_exclude,
)
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit
from guardhub_api.common.errors import ConflictError, NotFoundError, UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.db.models import ActiveConsent, Module, Project, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.contract_gen import ACTIVE_CHECK_IDS
from guardhub_api.projects.scanning import ScanTarget, ensure_fresh_ownership
from guardhub_api.scans.queue import JOBS_STREAM, STREAM_MAXLEN

CUSTOMER_CHECKS: tuple[str, ...] = tuple(c for c in ACTIVE_CHECK_IDS if c != "active_idor")
Lock = Literal[
    "customer_go",
    "terms_final",
    "oob_live",
    "approval",
    "modules",
    "kill",
    "scanner",
    "site_verified",
]


class Readiness(BaseModel):
    available: bool
    blocked_by: list[Lock]
    terms_version: str | None
    checks: list[str]
    running_scan_id: uuid.UUID | None


class StartRequest(BaseModel):
    checks: list[str] = Field(min_length=1, max_length=len(CUSTOMER_CHECKS))
    exclude: list[str] = Field(default_factory=list, max_length=MAX_EXCLUDED_PATHS)
    terms_version: str = Field(min_length=1, max_length=40)
    accept_terms: bool


class Started(BaseModel):
    scan_id: uuid.UUID


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="user", user_id=claims.user_id)  # the customer's own rows only (RLS)


def _terms() -> tuple[str, str] | None:
    s = get_settings()
    version, digest = s.active_tos_version.strip(), s.active_tos_sha256.strip().lower()
    if not version or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        return None
    return version, digest


async def _own_site(claims: SessionClaims, project_id: uuid.UUID) -> Project:
    async with db_session(_ctx(claims)) as session:
        project = await session.get(Project, project_id)
    if project is None or project.user_id != claims.user_id:
        raise NotFoundError("project_not_found", "Project not found.")
    if project.kind != "site":
        raise UnprocessableError("active_sites_only", "Active tests run on websites only.")
    return project


async def _modules_on(checks: list[str]) -> set[str]:
    async with db_session(DbContext.system()) as session:
        rows = await session.execute(
            select(Module.key).where(
                Module.key.in_(checks), Module.enabled_global.is_(True), Module.maintenance.is_(False)
            )
        )
        return set(rows.scalars())


async def _locks(redis: Redis, project: Project, checks: list[str]) -> list[Lock]:
    """Every lock that does not allow the scan, in order (empty: all hold)."""
    s = get_settings()
    blocked: list[Lock] = []
    switch, oob = await _scanner_state(redis)
    if not s.customer_active_testing_go:
        blocked.append("customer_go")
    if _terms() is None:
        blocked.append("terms_final")
    if not oob:
        blocked.append("oob_live")
    if not s.active_testing_approved:
        blocked.append("approval")
    if not checks or set(checks) - await _modules_on(checks):
        blocked.append("modules")
    if await _kill_engaged(redis):
        blocked.append("kill")
    if switch != "on":
        blocked.append("scanner")
    if project.ownership_verified_at is None:
        blocked.append("site_verified")
    return blocked


async def _running(redis: Redis, project: Project) -> uuid.UUID | None:
    held = await redis.get(ORIGIN_LOCK_PREFIX + ScanTarget.of(project).origin)
    if not held:
        return None
    try:
        return uuid.UUID(held.decode() if isinstance(held, bytes) else str(held))
    except ValueError:
        return None


async def readiness(claims: SessionClaims, redis: Redis, project_id: uuid.UUID) -> Readiness:
    project = await _own_site(claims, project_id)
    offered = sorted(await _modules_on(list(CUSTOMER_CHECKS)))  # only the modules switched on
    blocked = await _locks(redis, project, offered)
    terms = _terms()
    return Readiness(
        available=not blocked,
        blocked_by=blocked,
        terms_version=terms[0] if terms else None,
        checks=offered,
        running_scan_id=await _running(redis, project),
    )


async def start(claims: SessionClaims, redis: Redis, project_id: uuid.UUID, req: StartRequest) -> Started:
    checks = sorted(set(req.checks))
    unknown = [c for c in checks if c not in CUSTOMER_CHECKS]
    if unknown:
        raise UnprocessableError("not_a_customer_active_check", f"Not offered: {', '.join(unknown)}")
    exclude = _valid_exclude(req.exclude)
    project = await _own_site(claims, project_id)
    blocked = await _locks(redis, project, checks)
    if blocked:
        raise UnprocessableError(
            "customer_active_not_live"
            if blocked[0] in ("customer_go", "terms_final", "oob_live")
            else "active_blocked",
            "Active testing is not available for this site yet.",
            {"blocked_by": ",".join(blocked)},
        )
    terms = _terms()
    assert terms is not None  # the terms lock held
    if not req.accept_terms or req.terms_version != terms[0]:
        raise UnprocessableError("terms_not_accepted", "Accept the current active-testing terms first.")
    target = ScanTarget.of(project)
    await ensure_fresh_ownership(redis, target, ctx=_ctx(claims), actor=f"user:{claims.user_id}")  # §9.2
    scan_id = uuid.uuid4()
    lock = ORIGIN_LOCK_PREFIX + target.origin
    if not await redis.set(lock, str(scan_id), nx=True, ex=ORIGIN_LOCK_SECONDS):
        raise ConflictError("active_scan_running", "An active scan of this site is already running.")
    try:
        consent_id = await _record(
            claims, project=project, scan_id=scan_id, checks=checks, exclude=exclude, terms=terms
        )
        payload = {
            "v": 1,
            "kind": "active_scan",
            "job_id": str(uuid.uuid4()),
            "scan_id": str(scan_id),
            "target": target.origin,
            "checks": checks,
            "deadline_seconds": ACTIVE_DEADLINE_SECONDS,
            "token": target.token,  # the scanner proves ownership again before the first request
            "consent_id": str(consent_id),
            "exclude": exclude,
            "session_key": "",
        }
        await redis.xadd(
            JOBS_STREAM, {"payload": json.dumps(payload)}, maxlen=STREAM_MAXLEN, approximate=True
        )
    except Exception:
        if await redis.get(lock) in (str(scan_id), str(scan_id).encode()):
            await redis.delete(lock)
        raise
    return Started(scan_id=scan_id)


async def _record(
    claims: SessionClaims,
    *,
    project: Project,
    scan_id: uuid.UUID,
    checks: list[str],
    exclude: list[str],
    terms: tuple[str, str],
) -> uuid.UUID:
    consent_id = uuid.uuid4()
    origin = ScanTarget.of(project).origin
    async with db_session(_ctx(claims)) as session:
        session.add(
            ActiveConsent(
                id=consent_id,
                user_id=claims.user_id,
                project_id=project.id,
                origin=origin,
                excluded_paths=exclude,
                checks=checks,
                consent_version=f"customer-{terms[0]}",
                consent_sha256=terms[1],
            )
        )
        session.add(
            Scan(
                id=scan_id,
                user_id=claims.user_id,
                project_id=project.id,
                target_url=origin,
                checks=checks,
                trigger="manual",
            )
        )
        await audit.record(
            session,
            actor=f"user:{claims.user_id}",
            action="active.scan.started",
            target=str(scan_id),
            metadata={
                "origin": origin,
                "checks": ",".join(checks),
                "exclude": ",".join(exclude),
                "consent_id": str(consent_id),
                "terms": terms[0],
                "project_id": str(project.id),
            },
        )
    return consent_id


async def stop(claims: SessionClaims, redis: Redis, project_id: uuid.UUID, scan_id: uuid.UUID) -> None:
    """The customer's own stop: the per-scan kill key, honoured by the scanner within a second."""
    project = await _own_site(claims, project_id)
    async with db_session(_ctx(claims)) as session:
        scan = await session.get(Scan, scan_id)
        if scan is None or scan.project_id != project.id or not set(scan.checks) & set(ACTIVE_CHECK_IDS):
            raise NotFoundError("scan_not_found", "Scan not found.")
        await kill.engage(redis, scan_id)
        await audit.record(
            session,
            actor=f"user:{claims.user_id}",
            action="active.scan.stopped",
            target=str(scan_id),
            metadata={"by": "customer"},
        )
