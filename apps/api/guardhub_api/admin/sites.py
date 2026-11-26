"""Verified sites (profile prompt, item 2): every site an admin has proven, in one place.

Two sources, both the calling admin's own rows only:

- the admin's trusted domains (ADR-0003; revoked ones are left out), and
- the admin's own website projects (proven directly, or through a trusted domain).

A project proven through a trusted domain is listed under that domain, not twice. Each row gets
one status, computed here and nowhere else:

- `verified`: the proof is current (an active domain proven within 30 days; a project proven
  within REVERIFY_AFTER, or one whose trusted domain covers it right now);
- `expired`: the proof was valid but is older than its window; the next scan re-proves it;
- `failed`: the last check failed (a suspended domain, a project whose schedule stopped because
  ownership was lost, or a trusted-domain project whose domain no longer covers it);
- `pending`: never proven.

Re-verifying runs the existing proof flows (the scanner fetches the token once). Nothing here
grants a scan: the scan paths still ask `ensure_fresh_ownership` / `require_trusted_domain`
(§9.2), so this page cannot weaken ownership proof.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import select

from guardhub_api.admin.trusted_domains import service as td_service
from guardhub_api.admin.trusted_domains.ownership import PROOF_MAX_AGE, TRUSTED_DOMAIN_METHOD
from guardhub_api.admin.trusted_domains.router import TrustedDomainsAdmin
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common.errors import NotFoundError
from guardhub_api.common.redis import get_redis
from guardhub_api.db.models import AdminTrustedDomain, Project
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.projects import service as project_service
from guardhub_api.projects.scanning import REVERIFY_AFTER

SiteStatus = Literal["verified", "expired", "failed", "pending"]
SiteSource = Literal["trusted_domain", "project"]


class SiteView(BaseModel):
    source: SiteSource
    id: uuid.UUID  # the trusted domain's id, or the project's id
    origin: str
    host: str
    name: str | None
    status: SiteStatus
    method: str | None
    last_verified_at: datetime | None
    last_checked_at: datetime | None
    last_error: str | None
    project_ids: list[uuid.UUID]  # projects proven through this row (trusted domain) or itself
    trusted_domain_status: str | None  # pending | active | suspended (trusted-domain rows)


def domain_status(domain: AdminTrustedDomain, now: datetime) -> SiteStatus:
    if domain.status == "suspended":
        return "failed"
    if domain.status != "active" or domain.verified_at is None:
        return "pending"
    if now - domain.verified_at > PROOF_MAX_AGE:
        return "expired"
    return "verified"


def project_status(project: Project, now: datetime, covering: AdminTrustedDomain | None) -> SiteStatus:
    if project.ownership_method == TRUSTED_DOMAIN_METHOD:
        # Valid only while an active, recently proven domain covers the exact origin.
        return domain_status(covering, now) if covering is not None else "failed"
    if project.ownership_verified_at is None:
        return "pending"
    if project.schedule_paused_reason == "ownership_lost":
        return "failed"
    if now - project.ownership_verified_at > REVERIFY_AFTER:
        return "expired"
    return "verified"


def _host(origin: str) -> str:
    return origin.split("://", 1)[-1]


def build(domains: list[AdminTrustedDomain], projects: list[Project], now: datetime) -> list[SiteView]:
    """Merge the two sources into one list (pure: unit-tested without a database)."""
    by_origin = {d.target_origin: d for d in domains}
    linked: dict[uuid.UUID, list[uuid.UUID]] = {d.id: [] for d in domains}
    rows: list[SiteView] = []
    for p in projects:
        if p.kind != "site":
            continue
        covering = by_origin.get(p.target_url)
        if p.ownership_method == TRUSTED_DOMAIN_METHOD and covering is not None:
            linked[covering.id].append(p.id)
            continue
        status = project_status(p, now, covering if p.ownership_method == TRUSTED_DOMAIN_METHOD else None)
        rows.append(
            SiteView(
                source="project",
                id=p.id,
                origin=p.target_url,
                host=_host(p.target_url),
                name=p.name,
                status=status,
                method=p.ownership_method,
                last_verified_at=p.ownership_verified_at,
                last_checked_at=p.ownership_verified_at,
                last_error=(
                    "trusted_domain_gone"
                    if p.ownership_method == TRUSTED_DOMAIN_METHOD
                    else ("ownership_lost" if p.schedule_paused_reason == "ownership_lost" else None)
                ),
                project_ids=[p.id],
                trusted_domain_status=None,
            )
        )
    for d in domains:
        rows.append(
            SiteView(
                source="trusted_domain",
                id=d.id,
                origin=d.target_origin,
                host=d.host,
                name=None,
                status=domain_status(d, now),
                method=d.method,
                last_verified_at=d.verified_at,
                last_checked_at=d.last_checked_at,
                last_error=d.last_check_error if d.status != "active" else None,
                project_ids=linked[d.id],
                trusted_domain_status=d.status,
            )
        )
    order = {"failed": 0, "expired": 1, "pending": 2, "verified": 3}
    return sorted(rows, key=lambda r: (order[r.status], r.host))


async def list_sites(claims: SessionClaims) -> list[SiteView]:
    async with db_session(DbContext(role="admin", user_id=claims.user_id)) as session:
        domains = list(
            (
                await session.execute(
                    select(AdminTrustedDomain).where(
                        AdminTrustedDomain.admin_user_id == claims.user_id,
                        AdminTrustedDomain.status != "revoked",
                    )
                )
            ).scalars()
        )
        projects = list(
            (await session.execute(select(Project).where(Project.user_id == claims.user_id))).scalars()
        )
    return build(domains, projects, datetime.now(UTC))


async def reverify(
    redis: Redis, claims: SessionClaims, source: SiteSource, item_id: uuid.UUID
) -> list[SiteView]:
    """One click: run the existing proof for this row (a trusted domain, or a directly proven
    project). A trusted-domain project is re-proven through its domain."""
    if source == "trusted_domain":
        await td_service.verify_domain(redis, claims, item_id)
        return await list_sites(claims)
    async with db_session(DbContext(role="admin", user_id=claims.user_id)) as session:
        project = await session.get(Project, item_id)
        if project is None or project.user_id != claims.user_id or project.kind != "site":
            raise NotFoundError("project_not_found", "Project not found.")
        method, origin = project.ownership_method, project.target_url
        domain_id = (
            await session.execute(
                select(AdminTrustedDomain.id).where(
                    AdminTrustedDomain.admin_user_id == claims.user_id,
                    AdminTrustedDomain.target_origin == origin,
                    AdminTrustedDomain.status != "revoked",
                )
            )
        ).scalar_one_or_none()
    if method == TRUSTED_DOMAIN_METHOD and domain_id is not None:
        await td_service.verify_domain(redis, claims, domain_id)
    else:
        await project_service.verify_project(redis, claims, item_id)
    return await list_sites(claims)


router = APIRouter(prefix="/admin/sites", tags=["admin"])


@router.get("")
async def get_sites(claims: TrustedDomainsAdmin) -> list[SiteView]:
    return await list_sites(claims)


@router.post("/{source}/{item_id}/reverify")
async def post_reverify(
    source: SiteSource, item_id: uuid.UUID, claims: TrustedDomainsAdmin
) -> list[SiteView]:
    return await reverify(get_redis(), claims, source, item_id)
