"""Scan orchestration: create and queue scans, and build localised views (router → service → repo).

Flow: create a `scans` row (queued) → commit → XADD a job to the scanner. If enqueueing fails,
the scan is marked failed so the user never waits on a job that doesn't exist. Views merge the
DB status with the live Redis progress hash (§8.2 visible scan).
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass

from redis.asyncio import Redis
from redis.exceptions import RedisError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.auth.security import SessionClaims
from guardhub_api.billing import service as billing
from guardhub_api.common.errors import NotFoundError, ServiceUnavailableError, UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.db.models import Module, Scan
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.catalog import check_name, render_finding
from guardhub_api.findings.scoring import count_by_severity, severity_rank
from guardhub_api.modules.registry import enabled_check_ids
from guardhub_api.platform import service as platform
from guardhub_api.scans import queue, repository
from guardhub_api.scans.schemas import (
    EvidenceView,
    FindingView,
    ProgressItem,
    ScanSummary,
    ScanTrigger,
    ScanView,
    SeverityCounts,
)

log = logging.getLogger("guardhub.scans")

_CHECK_STATUSES = {"queued", "running", "done", "failed"}


@dataclass(frozen=True, slots=True)
class RepoJob:
    """A repository scan (ADR-0006): owner/name plus the token narrowed to that repository."""

    full_name: str
    token: str


async def _within_plan(
    session: AsyncSession, user_id: uuid.UUID, checks: list[str], *, manual: bool
) -> list[str]:
    limits = (
        await billing.check_manual_scan(session, user_id) if manual else await billing.limits_for(user_id)
    )
    ranks = await billing.plan_rank_for_checks(session)
    tiers = dict(
        (await session.execute(select(Module.key, Module.min_plan).where(Module.key.in_(checks)))).all()
    )
    return [c for c in checks if ranks.get(tiers.get(c, "free"), 0) <= limits.rank]


async def create_and_enqueue(
    redis: Redis,
    *,
    target: str,
    project_id: uuid.UUID | None,
    user_id: uuid.UUID | None,
    verification_id: uuid.UUID | None,
    public_token_hash: str | None,
    ctx: DbContext,
    trigger: ScanTrigger = "manual",
    repo: RepoJob | None = None,
) -> Scan:
    await platform.require_no_maintenance()
    deadline = await platform.int_value("scan.deadline_seconds")
    async with db_session(ctx) as session:
        checks = await enabled_check_ids(session, "repo" if repo else "site")
        if user_id is not None:  # the account's plan (Phase 5C): module tier, manual-scan limits
            checks = await _within_plan(session, user_id, checks, manual=trigger == "manual")
        if not checks:
            raise UnprocessableError("no_checks_enabled", "All checks are currently disabled.")
        scan = await repository.add(
            session,
            Scan(
                project_id=project_id,
                user_id=user_id,
                verification_id=verification_id,
                target_url=target,
                status="queued",
                trigger=trigger,
                checks=checks,
                public_token_hash=public_token_hash,
            ),
        )
    try:
        if repo is not None:
            await queue.enqueue_repo_scan(
                redis,
                scan_id=scan.id,
                repo=repo.full_name,
                token=repo.token,
                checks=checks,
                deadline_seconds=deadline,
            )
        else:
            await queue.enqueue_scan(
                redis,
                scan_id=scan.id,
                target=target,
                checks=checks,
                deadline_seconds=deadline,
            )
    except RedisError as exc:
        log.exception("enqueue_failed", extra={"scan_id": str(scan.id)})
        async with db_session(DbContext.system()) as session:
            await repository.mark_failed(session, scan.id, "queue_unavailable")
        raise ServiceUnavailableError("queue_unavailable", "Scanning is temporarily unavailable.") from exc
    return scan


def _summary(scan: Scan, counts: SeverityCounts) -> ScanSummary:
    return ScanSummary(
        id=scan.id,
        project_id=scan.project_id,
        target_url=scan.target_url,
        status=scan.status,
        trigger=scan.trigger,
        score=scan.score,
        finding_counts=counts,
        failed_checks=list(scan.failed_checks or []),
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        error=scan.error,
    )


async def summaries(session: AsyncSession, scans: list[Scan]) -> list[ScanSummary]:
    counts = await repository.severity_counts(session, [s.id for s in scans])
    return [_summary(s, SeverityCounts(**counts[s.id])) for s in scans]


def _progress(scan: Scan, live: dict[str, str], locale: str) -> list[ProgressItem]:
    items: list[ProgressItem] = []
    for check_id in scan.checks:
        state = live.get(check_id)
        if scan.status == "done":
            state = state if state in ("done", "failed") else "done"
        elif state not in _CHECK_STATUSES:
            state = "failed" if scan.status in ("failed", "cancelled") else "queued"
        items.append(ProgressItem(check_id=check_id, name=check_name(check_id, locale), status=state))
    return items


async def owned_view(redis: Redis, claims: SessionClaims, scan_id: uuid.UUID, locale: str) -> ScanView:
    async with db_session(DbContext.for_user(claims.user_id, claims.role)) as session:
        scan = await repository.get(session, scan_id)
        if scan is None or scan.user_id != claims.user_id:
            raise NotFoundError("scan_not_found", "Scan not found.")
        return await build_view(session, redis, scan, locale)


async def build_view(session: AsyncSession, redis: Redis, scan: Scan, locale: str) -> ScanView:
    cipher = get_settings().keyring
    findings: list[FindingView] = []
    for finding, ev in await repository.findings_with_evidence(session, scan.id):
        texts = render_finding(finding.check_id, finding.finding_key, dict(finding.params), locale)
        evidence_view = None
        if ev is not None:
            evidence_view = EvidenceView(
                kind=ev.kind,
                location=ev.location,
                redacted_payload=cipher.decrypt(ev.redacted_payload, associated_data=str(ev.id).encode()),
            )
        findings.append(
            FindingView(
                id=finding.id,
                check_id=finding.check_id,
                finding_key=finding.finding_key,
                severity=finding.severity,
                title=texts.title,
                summary=texts.summary,
                why=texts.why,
                fix=texts.fix,
                evidence=evidence_view,
                status=finding.status,
            )
        )
    findings.sort(key=lambda f: (severity_rank(f.severity), f.check_id, f.finding_key))
    live: dict[str, str] = {}
    if scan.status in ("queued", "running"):
        try:
            live = await queue.read_progress(redis, scan.id)
        except RedisError:
            log.warning("progress_unavailable", extra={"scan_id": str(scan.id)})
    counts = SeverityCounts(**count_by_severity(f.severity for f in findings))
    return ScanView(
        **_summary(scan, counts).model_dump(), progress=_progress(scan, live, locale), findings=findings
    )
