"""Scan comparison service (docs/architecture.md §8.3): loads two scans, runs the pure diff engine
(`scans.diff`) and renders localised items. Shared by the diff endpoint and the alert job.

Reads only findings (never evidence). Owner checks are explicit on top of RLS, because RLS also
lets the admin role read other users' rows.
"""

from __future__ import annotations

import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.auth.security import SessionClaims
from guardhub_api.common.errors import NotFoundError, UnprocessableError
from guardhub_api.db.models import Finding, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.catalog import render_finding
from guardhub_api.scans import repository
from guardhub_api.scans.diff import (
    DiffFinding,
    DiffResult,
    ScanSnapshot,
    appeared_fingerprints,
    compute_diff,
    sort_by_severity_then_title,
)
from guardhub_api.scans.schemas import DiffItem, ScanDiffView


def snapshot(scan: Scan, findings: list[Finding]) -> ScanSnapshot:
    return ScanSnapshot(
        scan_id=scan.id,
        checks=tuple(scan.checks or ()),
        failed_checks=frozenset(scan.failed_checks or ()),
        findings=tuple(
            DiffFinding(
                fingerprint=f.fingerprint,
                check_id=f.check_id,
                finding_key=f.finding_key,
                severity=f.severity,
                params=dict(f.params or {}),
            )
            for f in findings
        ),
    )


async def resolve_base(session: AsyncSession, scan: Scan, against: uuid.UUID | None) -> Scan | None:
    """Default: the latest done scan created before `scan`. An explicit `against` must be an earlier
    done scan of the same project, otherwise 422 `invalid_comparison` (also when it isn't visible)."""
    assert scan.project_id is not None
    if against is None:
        return await repository.previous_done(session, scan.project_id, scan.created_at)
    base = await repository.get(session, against)
    if (
        base is None
        or base.id == scan.id
        or base.project_id != scan.project_id
        or base.user_id != scan.user_id
        or base.status != "done"
        or base.created_at >= scan.created_at
    ):
        raise UnprocessableError(
            "invalid_comparison", "Compare with an earlier finished scan of the same project."
        )
    return base


async def diff_scans(session: AsyncSession, scan: Scan, base: Scan | None) -> DiffResult:
    assert scan.project_id is not None
    current = snapshot(scan, await repository.findings_for_diff(session, scan.id))
    if base is None:
        return compute_diff(current, None)
    previous = snapshot(base, await repository.findings_for_diff(session, base.id))
    seen = await repository.fingerprints_seen_before(
        session, scan.project_id, base.created_at, appeared_fingerprints(current, previous)
    )
    return compute_diff(current, previous, seen)


def render_items(items: tuple[DiffFinding, ...], locale: str) -> list[DiffItem]:
    rendered = []
    for f in items:
        texts = render_finding(f.check_id, f.finding_key, dict(f.params), locale)
        rendered.append(
            DiffItem(
                fingerprint=f.fingerprint,
                check_id=f.check_id,
                finding_key=f.finding_key,
                severity=f.severity,
                title=texts.title,
                summary=texts.summary,
            )
        )
    return sort_by_severity_then_title(rendered, lambda i: i.severity, lambda i: i.title)


def diff_view(scan: Scan, base: Scan | None, result: DiffResult, locale: str) -> ScanDiffView:
    assert scan.project_id is not None
    base_score = base.score if base is not None else None
    delta = scan.score - base_score if scan.score is not None and base_score is not None else None
    return ScanDiffView(
        scan_id=scan.id,
        base_scan_id=result.base_scan_id,
        project_id=scan.project_id,
        score=scan.score,
        base_score=base_score,
        score_delta=delta,
        compared_checks=list(result.compared_checks),
        skipped_checks=list(result.skipped_checks),
        new=render_items(result.new, locale),
        regressed=render_items(result.regressed, locale),
        fixed=render_items(result.fixed, locale),
        unchanged_count=result.unchanged_count,
    )


async def owned_diff(
    claims: SessionClaims, scan_id: uuid.UUID, against: uuid.UUID | None, locale: str
) -> ScanDiffView:
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        scan = await repository.get(session, scan_id)
        if scan is None or scan.user_id != claims.user_id or scan.project_id is None:
            raise NotFoundError("scan_not_found", "Scan not found.")
        if scan.status != "done":
            raise UnprocessableError("scan_not_done", "This scan has not finished yet.")
        base = await resolve_base(session, scan, against)
        return diff_view(scan, base, await diff_scans(session, scan, base), locale)
