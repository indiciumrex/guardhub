"""Trusted-domain business logic (ADR-0003): add, verify, revoke, and scan through a domain.

Callers must already have passed `trusted_domains_admin` (role re-read from the DB, MFA
complete). Everything runs in the caller's 'admin' RLS context, and every lookup also filters
on the caller's id, so one admin can never see or use another admin's domains. Ownership is
checked by the scanner's verify job, exactly like project verification; a scan is only queued
after `ownership.require_trusted_domain` confirms an active, recently proven domain for the
exact origin. Each state change writes one AuditLog row.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import cast, get_args

from redis.asyncio import Redis
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.admin.trusted_domains import repository
from guardhub_api.admin.trusted_domains.ownership import (
    PROOF_MAX_AGE,
    TRUSTED_DOMAIN_METHOD,
    require_trusted_domain,
)
from guardhub_api.admin.trusted_domains.schemas import TrustedDomainStatus, TrustedDomainView
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit, ratelimit
from guardhub_api.common.errors import ConflictError, NotFoundError, UnprocessableError
from guardhub_api.common.urls import normalize_origin
from guardhub_api.config import get_settings
from guardhub_api.db.models import AdminTrustedDomain, Project
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.projects import repository as project_repo
from guardhub_api.projects.scanning import start_project_scan
from guardhub_api.projects.service import MAX_PROJECTS_PER_USER
from guardhub_api.projects.verification import instructions, new_token, prove_ownership
from guardhub_api.scans import repository as scan_repo
from guardhub_api.scans import service as scan_service
from guardhub_api.scans.schemas import ScanSummary

MAX_TRUSTED_DOMAINS_PER_ADMIN = 50
AUDIT_PREFIX = "admin.trusted_domain"


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="admin", user_id=claims.user_id)


def _actor(claims: SessionClaims) -> str:
    return f"admin:{claims.user_id}"


def host_of_origin(origin: str) -> str:
    """`https://example.com:8443` → `example.com:8443` (the origin is already normalised)."""
    return origin.split("://", 1)[1]


def _status(domain: AdminTrustedDomain) -> TrustedDomainStatus:
    if domain.status not in get_args(TrustedDomainStatus):
        raise ValueError(f"unexpected trusted domain status {domain.status!r}")
    return cast(TrustedDomainStatus, domain.status)


def _view(domain: AdminTrustedDomain) -> TrustedDomainView:
    return TrustedDomainView(
        id=domain.id,
        host=domain.host,
        target_origin=domain.target_origin,
        status=_status(domain),
        verification=instructions(domain.target_origin, domain.verification_token),
        method=domain.method,
        verified_at=domain.verified_at,
        last_checked_at=domain.last_checked_at,
        suspended_at=domain.suspended_at,
        created_at=domain.created_at,
    )


def mark_proven(domain: AdminTrustedDomain, method: str, now: datetime) -> str | None:
    """Record a successful proof. Returns the audit verb for the transition, if any."""
    previous = domain.status
    domain.status = "active"
    domain.method = method
    domain.verified_at = now
    domain.last_checked_at = now
    domain.last_check_error = None
    domain.suspended_at = None
    if previous == "suspended":
        return "reactivated"
    if previous == "pending":
        return "verified"
    return None


def mark_failed(domain: AdminTrustedDomain, reason: str, now: datetime) -> bool:
    """Record a failed proof check. An active domain is suspended; returns True when it was."""
    domain.last_checked_at = now
    domain.last_check_error = reason[:64]
    if domain.status == "active":
        domain.status = "suspended"
        domain.suspended_at = now
        return True
    return False


async def _get(
    session: AsyncSession, claims: SessionClaims, domain_id: uuid.UUID, *, for_update: bool = False
) -> AdminTrustedDomain:
    domain = await repository.get_live(session, claims.user_id, domain_id, for_update=for_update)
    if domain is None:  # someone else's, revoked, or missing: all look the same
        raise NotFoundError("trusted_domain_not_found", "Trusted domain not found.")
    return domain


async def list_domains(claims: SessionClaims) -> list[TrustedDomainView]:
    async with db_session(_ctx(claims)) as session:
        return [_view(d) for d in await repository.list_live(session, claims.user_id)]


async def add_domain(claims: SessionClaims, target_url: str) -> TrustedDomainView:
    origin = normalize_origin(target_url, allow_private_hosts=get_settings().private_host_allowlist)
    host = host_of_origin(origin)
    try:
        async with db_session(_ctx(claims)) as session:
            if await repository.live_for_host(session, claims.user_id, host) is not None:
                raise ConflictError("trusted_domain_exists", "This host is already in your trusted domains.")
            if await repository.count_live(session, claims.user_id) >= MAX_TRUSTED_DOMAINS_PER_ADMIN:
                raise UnprocessableError("trusted_domain_limit_reached", "Trusted domain limit reached.")
            domain = await repository.add(
                session,
                AdminTrustedDomain(
                    admin_user_id=claims.user_id,
                    host=host,
                    target_origin=origin,
                    status="pending",
                    verification_token=new_token(),
                ),
            )
            await audit.record(
                session,
                actor=_actor(claims),
                action=f"{AUDIT_PREFIX}.added",
                target=str(domain.id),
                metadata={"host": host, "origin": origin},
            )
            return _view(domain)
    except IntegrityError as exc:  # a concurrent add of the same host won the unique index
        raise ConflictError("trusted_domain_exists", "This host is already in your trusted domains.") from exc


async def _record_failed_proof(claims: SessionClaims, domain_id: uuid.UUID, reason: str) -> None:
    async with db_session(_ctx(claims)) as session:
        domain = await repository.get_live(session, claims.user_id, domain_id, for_update=True)
        if domain is None:
            return
        if mark_failed(domain, reason, datetime.now(UTC)):
            await audit.record(
                session,
                actor=_actor(claims),
                action=f"{AUDIT_PREFIX}.suspended",
                target=str(domain.id),
                metadata={"host": domain.host, "reason": reason},
            )


async def verify_domain(redis: Redis, claims: SessionClaims, domain_id: uuid.UUID) -> TrustedDomainView:
    """Ask the scanner to check the proof. Success → active; failure keeps a pending domain
    pending, suspends an active one, and raises 422 `ownership_not_verified`."""
    await ratelimit.enforce(redis, "verify-trusted-domain", str(domain_id), limit=10, window=600)
    async with db_session(_ctx(claims)) as session:
        domain = await _get(session, claims, domain_id)
        origin, token = domain.target_origin, domain.verification_token
    try:
        method = await prove_ownership(redis, origin=origin, token=token)
    except UnprocessableError as exc:
        await _record_failed_proof(claims, domain_id, (exc.details or {}).get("reason", "not_found"))
        raise
    async with db_session(_ctx(claims)) as session:
        domain = await _get(session, claims, domain_id, for_update=True)  # revoked meanwhile → 404
        transition = mark_proven(domain, method, datetime.now(UTC))
        await audit.record(
            session,
            actor=_actor(claims),
            action=f"{AUDIT_PREFIX}.{transition or 'verified'}",
            target=str(domain.id),
            metadata={"host": domain.host, "method": method},
        )
        return _view(domain)


async def revoke_domain(claims: SessionClaims, domain_id: uuid.UUID) -> None:
    async with db_session(_ctx(claims)) as session:
        domain = await _get(session, claims, domain_id, for_update=True)
        domain.status = "revoked"
        domain.revoked_at = datetime.now(UTC)
        await audit.record(
            session,
            actor=_actor(claims),
            action=f"{AUDIT_PREFIX}.revoked",
            target=str(domain.id),
            metadata={"host": domain.host},
        )


async def scan_domain(redis: Redis, claims: SessionClaims, domain_id: uuid.UUID) -> ScanSummary:
    """Create (or reuse) the admin's project for the domain's exact origin and queue a scan."""
    await ratelimit.enforce(redis, "trusted-domain-scan", str(domain_id), limit=10, window=3600)
    async with db_session(_ctx(claims)) as session:
        domain = await _get(session, claims, domain_id)
        if domain.status != "active":
            raise UnprocessableError(
                "trusted_domain_inactive", "Verify this trusted domain before scanning it."
            )
        origin = domain.target_origin
        stale = domain.verified_at is None or datetime.now(UTC) - domain.verified_at > PROOF_MAX_AGE
    if stale:  # the background re-check hasn't run lately: prove it again now (suspends on failure)
        await verify_domain(redis, claims, domain_id)
    # The authoritative gate: DB role is admin, domain active + recently proven, exact origin.
    await require_trusted_domain(claims.user_id, origin)

    now = datetime.now(UTC)
    async with db_session(_ctx(claims)) as session:
        project = await project_repo.by_target(session, claims.user_id, origin)
        if project is None:
            if await project_repo.count_for_user(session, claims.user_id) >= MAX_PROJECTS_PER_USER:
                raise UnprocessableError("project_limit_reached", "Project limit reached.")
            project = await project_repo.add(
                session,
                Project(
                    user_id=claims.user_id,
                    name=host_of_origin(origin)[:120],
                    target_url=origin,
                    verification_token=new_token(),
                    ownership_verified_at=now,
                    ownership_method=TRUSTED_DOMAIN_METHOD,
                ),
            )
            await audit.record(
                session,
                actor=f"user:{claims.user_id}",
                action="project.create",
                target=str(project.id),
                metadata={"ownership_method": TRUSTED_DOMAIN_METHOD},
            )
        else:
            if await scan_repo.has_active(session, project.id):
                raise ConflictError("scan_in_progress", "A scan is already running for this project.")
            project.ownership_verified_at = now
            project.ownership_method = TRUSTED_DOMAIN_METHOD
        project_id = project.id

    # one scan path for every trigger (projects.scanning): re-checks the trusted domain itself
    scan = await start_project_scan(
        redis, project_id=project_id, ctx=_ctx(claims), actor=_actor(claims), trigger="manual"
    )
    async with db_session(_ctx(claims)) as session:
        await audit.record(
            session,
            actor=_actor(claims),
            action=f"{AUDIT_PREFIX}.scan",
            target=str(domain_id),
            metadata={"host": host_of_origin(origin), "project": str(project_id), "scan": str(scan.id)},
        )
        return (await scan_service.summaries(session, [scan]))[0]
