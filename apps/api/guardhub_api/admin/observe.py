"""Super-admin observe-only scans (profile prompt, item 3): a passive look at a site WITHOUT an
ownership proof. Not a bypass of §9.2:

- only observe-only checks run (check-ids.json "observe": true: TLS, headers, cookies, DNS
  records, page content, library versions). No payload, no path probing, no credential attempt.
  Everything else (exposed files, admin pages, default credentials, zone transfers, secrets,
  takeover discovery, every active test) still needs a verified site, with no exception;
- the scanner receives a separate job kind (`observe_scan`) and refuses the whole job if any other
  check is in it, so a bug here cannot widen what an unproven target receives;
- only a super-admin (an admin whose id is listed in SUPER_ADMIN_IDS on the server; role re-read
  from the database, full two-factor session) can start one, and only while the server switch
  OBSERVE_SCAN_ENABLED is on (off by default);
- every scan needs the authorisation statement accepted, the relationship to the site and a note;
  all of it goes into the audit log before the scan is queued;
- active-test locks and the active scan paths are not touched.
"""

from __future__ import annotations

import hashlib
import uuid
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field
from redis.asyncio import Redis

from guardhub_api.admin.trusted_domains.router import trusted_domains_admin
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit, ratelimit
from guardhub_api.common.errors import NotFoundError, UnprocessableError
from guardhub_api.common.redis import get_redis
from guardhub_api.common.urls import normalize_origin
from guardhub_api.config import get_settings
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.contract_gen import ACTIVE_CHECK_IDS, OBSERVE_CHECK_IDS, SITE_CHECK_IDS
from guardhub_api.modules.registry import enabled_check_ids
from guardhub_api.scans import service as scan_service
from guardhub_api.scans.schemas import ScanSummary

STATEMENT_VERSION = "observe-2026-11-26"
STATEMENT = (
    "I am authorised to look at this site: I own or control it, or its owner or operator asked me "
    "to check it. GuardHub runs only observe-only checks (what any browser or mail server sees: "
    "TLS, headers, cookies, DNS records, page content and library versions), with no payloads, no "
    "path probing and no sign-in attempts. My name, this statement and my note are recorded."
)
STATEMENT_SHA256 = hashlib.sha256(STATEMENT.encode()).hexdigest()
AUDIT_PREFIX = "admin.observe_scan"

Relationship = Literal["owner", "client", "employer", "other"]


def super_admin_ids() -> frozenset[uuid.UUID]:
    out: set[uuid.UUID] = set()
    for raw in get_settings().super_admin_ids.split(","):
        part = raw.strip()
        if not part:
            continue
        try:
            out.add(uuid.UUID(part))
        except ValueError:
            continue  # a malformed entry grants nothing
    return frozenset(out)


async def super_admin(claims: Annotated[SessionClaims, Depends(trusted_domains_admin)]) -> SessionClaims:
    """Admin (DB role) + full MFA (trusted_domains_admin) AND listed as super-admin; else 404."""
    if claims.user_id not in super_admin_ids():
        raise NotFoundError("not_found", "Not found.")
    return claims


SuperAdmin = Annotated[SessionClaims, Depends(super_admin)]


class ObserveReadiness(BaseModel):
    enabled: bool  # the server switch OBSERVE_SCAN_ENABLED
    checks: list[str]  # observe-only checks that are switched on right now
    needs_verified_site: list[str]  # every other site check and every active check
    statement: str
    statement_version: str
    statement_sha256: str


class ObserveScanRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)
    relationship: Relationship
    note: str = Field(min_length=10, max_length=500)  # who asked / who owns it, in the admin's words
    statement_version: str = Field(max_length=64)
    accept_statement: bool
    checks: list[str] | None = Field(default=None, max_length=64)  # None = every observe-only check


def _needs_verified_site() -> list[str]:
    return [c for c in (*SITE_CHECK_IDS, *ACTIVE_CHECK_IDS) if c not in OBSERVE_CHECK_IDS]


async def readiness() -> ObserveReadiness:
    async with db_session(DbContext.system()) as session:
        enabled = await enabled_check_ids(session, "site")
    return ObserveReadiness(
        enabled=get_settings().observe_scan_enabled,
        checks=[c for c in OBSERVE_CHECK_IDS if c in enabled],
        needs_verified_site=_needs_verified_site(),
        statement=STATEMENT,
        statement_version=STATEMENT_VERSION,
        statement_sha256=STATEMENT_SHA256,
    )


async def start(redis: Redis, claims: SessionClaims, req: ObserveScanRequest) -> ScanSummary:
    if not get_settings().observe_scan_enabled:
        raise UnprocessableError("observe_scan_off", "Observe-only scans are switched off on the server.")
    if not req.accept_statement or req.statement_version != STATEMENT_VERSION:
        raise UnprocessableError("statement_required", "Accept the current authorisation statement first.")
    requested = list(dict.fromkeys(req.checks)) if req.checks else list(OBSERVE_CHECK_IDS)
    outside = [c for c in requested if c not in OBSERVE_CHECK_IDS]
    if outside:  # the boundary: anything beyond observation needs a verified site (§9.2)
        raise UnprocessableError(
            "ownership_required",
            "These checks need a verified site; they never run without an ownership proof.",
            {"checks": ",".join(outside)},
        )
    settings = get_settings()
    origin = normalize_origin(req.target_url, allow_private_hosts=settings.private_host_allowlist)
    await ratelimit.enforce(redis, "observe-scan", str(claims.user_id), limit=10, window=3600)
    note = " ".join(req.note.split())
    ctx = DbContext(role="admin", user_id=claims.user_id)
    actor = f"admin:{claims.user_id}"
    async with db_session(ctx) as session:  # the statement is on record before anything is queued
        await audit.record(
            session,
            actor=actor,
            action=f"{AUDIT_PREFIX}.declared",
            target=origin,
            metadata={
                "origin": origin,
                "relationship": req.relationship,
                "note": note,
                "statement_version": STATEMENT_VERSION,
                "statement_sha256": STATEMENT_SHA256,
                "checks": ",".join(requested),
            },
        )
    scan = await scan_service.create_and_enqueue(
        redis,
        target=origin,
        project_id=None,
        user_id=claims.user_id,
        verification_id=None,
        public_token_hash=None,
        ctx=ctx,
        trigger="observe",
        observe_checks=requested,
    )
    async with db_session(ctx) as session:
        await audit.record(
            session,
            actor=actor,
            action=f"{AUDIT_PREFIX}.queued",
            target=str(scan.id),
            metadata={"origin": origin, "checks": ",".join(scan.checks)},
        )
        return (await scan_service.summaries(session, [scan]))[0]


router = APIRouter(prefix="/admin/observe-scans", tags=["admin"])


@router.get("")
async def get_readiness(claims: SuperAdmin) -> ObserveReadiness:
    del claims
    return await readiness()


@router.post("", status_code=status.HTTP_202_ACCEPTED)
async def post_scan(body: ObserveScanRequest, claims: SuperAdmin) -> ScanSummary:
    return await start(get_redis(), claims, body)
