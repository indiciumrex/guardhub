"""Scan persistence queries (repository layer). Knows SQL, not HTTP or business rules.

All queries run inside an RLS-scoped session, so visibility is enforced by PostgreSQL too.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import Evidence, Finding, Scan


async def add(session: AsyncSession, scan: Scan) -> Scan:
    session.add(scan)
    await session.flush()
    await session.refresh(scan)
    return scan


async def get(session: AsyncSession, scan_id: uuid.UUID, *, for_update: bool = False) -> Scan | None:
    stmt = select(Scan).where(Scan.id == scan_id)
    if for_update:
        stmt = stmt.with_for_update()
    return (await session.execute(stmt)).scalar_one_or_none()


async def list_for_project(session: AsyncSession, project_id: uuid.UUID, limit: int = 100) -> list[Scan]:
    stmt = select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at.desc()).limit(limit)
    return list((await session.execute(stmt)).scalars().all())


async def latest_for_projects(session: AsyncSession, project_ids: list[uuid.UUID]) -> dict[uuid.UUID, Scan]:
    if not project_ids:
        return {}
    stmt = (
        select(Scan)
        .where(Scan.project_id.in_(project_ids))
        .distinct(Scan.project_id)
        .order_by(Scan.project_id, Scan.created_at.desc())
    )
    return {s.project_id: s for s in (await session.execute(stmt)).scalars().all() if s.project_id}


async def has_active(session: AsyncSession, project_id: uuid.UUID) -> bool:
    stmt = select(func.count()).where(Scan.project_id == project_id, Scan.status.in_(("queued", "running")))
    return int((await session.execute(stmt)).scalar_one()) > 0


async def list_recent(session: AsyncSession, limit: int, offset: int) -> list[Scan]:
    stmt = select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    return list((await session.execute(stmt)).scalars().all())


async def fail_stuck(session: AsyncSession, created_before: datetime, at: datetime) -> int:
    """Mark queued/running scans created before `created_before` as failed (timeout)."""
    result = await session.execute(
        update(Scan)
        .where(Scan.status.in_(("queued", "running")), Scan.created_at < created_before)
        .values(status="failed", error="timeout", finished_at=at)
        .returning(Scan.id)
    )
    return len(result.scalars().all())


async def mark_failed(
    session: AsyncSession, scan_id: uuid.UUID, error: str, at: datetime | None = None
) -> None:
    values: dict[str, object] = {"status": "failed", "error": error}
    if at is not None:
        values["finished_at"] = at
    await session.execute(update(Scan).where(Scan.id == scan_id).values(**values))


async def severity_counts(
    session: AsyncSession, scan_ids: list[uuid.UUID]
) -> dict[uuid.UUID, dict[str, int]]:
    out: dict[uuid.UUID, dict[str, int]] = defaultdict(dict)
    if scan_ids:
        rows = await session.execute(
            select(Finding.scan_id, Finding.severity, func.count())
            .where(Finding.scan_id.in_(scan_ids))
            .group_by(Finding.scan_id, Finding.severity)
        )
        for scan_id, severity, n in rows.all():
            out[scan_id][severity] = int(n)
    return {sid: out.get(sid, {}) for sid in scan_ids}


async def findings_with_evidence(
    session: AsyncSession, scan_id: uuid.UUID
) -> list[tuple[Finding, Evidence | None]]:
    rows = await session.execute(
        select(Finding, Evidence)
        .outerjoin(Evidence, Evidence.id == Finding.evidence_ref)
        .where(Finding.scan_id == scan_id)
    )
    return [(f, e) for f, e in rows.all()]


async def add_finding_with_evidence(session: AsyncSession, finding: Finding, evidence: Evidence) -> None:
    session.add(finding)
    await session.flush()
    evidence.finding_id = finding.id
    session.add(evidence)
    await session.flush()
    finding.evidence_ref = evidence.id
    await session.flush()
