"""Admin control centre (GUARDHUB_STANDARDS §8.3): overview, module centre, scan orchestration,
findings & risk, audit & monitoring.

Every function here is called only after `admin_session` (role re-read from the DB, MFA complete)
and reads under the 'admin' RLS context. Writes that customers' rows cannot accept under a role
context (cancelling a scan) run in the system context, after that admin check, and are audited
with the admin as actor. Nothing returned contains a secret: no tokens, password or TOTP data,
evidence payloads or raw IPs (audit rows carry a keyed IP hash).
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import httpx
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import and_, case, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.active import kill
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit
from guardhub_api.common.errors import ConflictError, NotFoundError, UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.db.models import (
    AuditLog,
    Evidence,
    Finding,
    FindingTriage,
    Module,
    Project,
    Scan,
    TargetVerification,
    User,
)
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.catalog import render_finding
from guardhub_api.findings.contract_gen import ACTIVE_CHECK_IDS
from guardhub_api.findings.scoring import SEVERITY_ORDER, SEVERITY_WEIGHTS, compute_score
from guardhub_api.findings.taxonomy import Classification, classify
from guardhub_api.health import service as health_svc
from guardhub_api.projects.scanning import start_project_scan
from guardhub_api.scans import repository as scan_repo
from guardhub_api.scans.queue import JOBS_STREAM, SCANNER_GROUP

log = logging.getLogger("guardhub.admin.center")

# Shared with the scanner (apps/scanner/internal/queue/info.go): keep the names in sync.
SCAN_CANCEL_PREFIX = "gh:scan:cancel:"
SCANNER_INFO_PREFIX = "gh:scanner:info:"
CANCEL_KEY_TTL_SECONDS = 3600

# The active-test limits are compiled into the scanner (apps/scanner/internal/active/breaker.go
# DefaultLimits, internal/queue/activescan.go deadlines; ADR-0008 §4). Shown, not configurable.
ACTIVE_LIMITS: dict[str, float] = {
    "requests_per_second": 1,
    "requests_per_scan": 300,
    "requests_per_module": 100,
    "consecutive_5xx_stop": 3,
    "latency_factor_stop": 3,
    "retry_after_max_seconds": 30,
    "deadline_seconds": 600,
    "deadline_max_seconds": 900,
}

Lifecycle = Literal["queued", "running", "completed", "failed", "timed_out", "cancelled"]
TriageStatus = Literal["verified", "accepted", "false_positive", "resolved"]
TRIAGE_STATUSES: tuple[str, ...] = ("verified", "accepted", "false_positive", "resolved")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="admin", user_id=claims.user_id)


def _actor(claims: SessionClaims) -> str:
    return f"admin:{claims.user_id}"


def lifecycle(status: str, error: str | None) -> Lifecycle:
    if status == "done":
        return "completed"
    if status == "failed" and error == "timeout":
        return "timed_out"
    if status in ("queued", "running", "failed", "cancelled"):
        return status  # type: ignore[return-value]
    return "failed"


# --------------------------------------------------------------------------------------------
# shared views
# --------------------------------------------------------------------------------------------


class ScanCounts(BaseModel):
    total: int = 0
    queued: int = 0
    running: int = 0
    completed: int = 0
    failed: int = 0
    timed_out: int = 0
    cancelled: int = 0
    last_24h: int = 0


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    total: int = 0


class ModuleRate(BaseModel):
    check_id: str
    runs: int
    failed: int
    success_rate: float | None


class QueueView(BaseModel):
    available: bool
    stream_length: int | None = None  # entries kept in gh:jobs (processed ones included)
    lag: int | None = None  # entries no scanner has read yet (the backlog)
    pending: int | None = None  # read by a scanner, not acknowledged yet (in progress)
    consumers: int | None = None
    busiest_idle_ms: int | None = None  # the most recently active consumer's idle time


class ScannerInfo(BaseModel):
    consumer: str = ""
    version: str = ""
    started_at: str = ""
    workers: int = 0
    check_concurrency: int = 0
    host_rps: float = 0
    host_burst: int = 0
    max_requests_per_scan: int = 0
    request_timeout_ms: int = 0
    active_enabled: bool = False
    active_oob: bool = False
    repo_scans: bool = False


class AuditDetail(BaseModel):
    id: int
    actor: str
    actor_email: str | None
    action: str
    target: str
    at: datetime
    changes: dict[str, str]  # before/after and other metadata (never secrets; ip_hash removed)
    ip_hash: str | None


class ErrorItem(BaseModel):
    source: Literal["scan", "module", "sentry"]
    at: datetime | None
    title: str
    detail: str
    count: int | None = None
    link: str | None = None


class SentryView(BaseModel):
    configured: bool
    issues: list[ErrorItem] = []
    error: str | None = None


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------


async def _scan_counts(session: AsyncSession) -> ScanCounts:
    rows = (
        await session.execute(select(Scan.status, Scan.error, func.count()).group_by(Scan.status, Scan.error))
    ).all()
    counts = ScanCounts()
    for status, error, n in rows:
        stage = lifecycle(status, error)
        setattr(counts, stage, getattr(counts, stage) + int(n))
        counts.total += int(n)
    since = datetime.now(UTC) - timedelta(hours=24)
    counts.last_24h = int(
        (
            await session.execute(select(func.count()).select_from(Scan).where(Scan.created_at >= since))
        ).scalar_one()
    )
    return counts


async def _open_findings(session: AsyncSession) -> SeverityCounts:
    """Findings of the latest completed scan of each target (what is exposed right now)."""
    latest = (
        select(Scan.id)
        .where(Scan.status == "done")
        .distinct(Scan.target_url)
        .order_by(Scan.target_url, Scan.finished_at.desc().nulls_last())
        .subquery()
    )
    rows = (
        await session.execute(
            select(Finding.severity, func.count())
            .where(Finding.scan_id.in_(select(latest.c.id)))
            .group_by(Finding.severity)
        )
    ).all()
    out = SeverityCounts()
    for severity, n in rows:
        if severity in SEVERITY_ORDER:
            setattr(out, severity, int(n))
            out.total += int(n)
    return out


async def _module_rates(session: AsyncSession, days: int = 7) -> list[ModuleRate]:
    """Per check: completed scans that ran it in the last `days`, and how many could not run it."""
    since = datetime.now(UTC) - timedelta(days=days)
    runs: dict[str, int] = dict(
        (
            await session.execute(
                text(
                    "SELECT c, count(*) FROM scans, unnest(checks) AS c "
                    "WHERE status = 'done' AND created_at >= :since GROUP BY c"
                ),
                {"since": since},
            )
        ).all()
    )
    failed: dict[str, int] = dict(
        (
            await session.execute(
                text(
                    "SELECT c, count(*) FROM scans, unnest(failed_checks) AS c "
                    "WHERE status = 'done' AND created_at >= :since GROUP BY c"
                ),
                {"since": since},
            )
        ).all()
    )
    out = []
    for check_id in sorted(set(runs) | set(failed)):
        n, f = int(runs.get(check_id, 0)), int(failed.get(check_id, 0))
        out.append(ModuleRate(check_id=check_id, runs=n, failed=f, success_rate=(n - f) / n if n else None))
    return out


async def _queue(redis: Redis) -> QueueView:
    try:
        length = int(await redis.xlen(JOBS_STREAM))
        groups = await redis.xinfo_groups(JOBS_STREAM)
        group = next((g for g in groups if str(g.get("name")) == SCANNER_GROUP), None)
        consumers = await redis.xinfo_consumers(JOBS_STREAM, SCANNER_GROUP) if group else []
    except Exception:
        log.warning("admin_queue_unavailable", exc_info=True)
        return QueueView(available=False)
    lag = group.get("lag") if group else None
    idle = [int(c.get("idle", 0)) for c in consumers]
    return QueueView(
        available=True,
        stream_length=length,
        lag=int(lag) if lag is not None else None,
        pending=int(group.get("pending", 0)) if group else None,
        consumers=len(consumers),
        busiest_idle_ms=min(idle) if idle else None,
    )


async def _scanners(redis: Redis) -> list[ScannerInfo]:
    out: list[ScannerInfo] = []
    try:
        keys = [k async for k in redis.scan_iter(match=SCANNER_INFO_PREFIX + "*", count=100)][:50]
        values = await redis.mget(keys) if keys else []
    except Exception:
        log.warning("admin_scanner_info_unavailable", exc_info=True)
        return out
    for raw in values:
        if not raw:
            continue
        try:
            out.append(ScannerInfo.model_validate(json.loads(raw)))
        except ValueError:
            continue
    return sorted(out, key=lambda s: s.consumer)


async def _emails(session: AsyncSession, actors: list[str]) -> dict[str, str]:
    ids = {m.group(0) for a in actors if (m := _UUID.search(a))}
    if not ids:
        return {}
    rows = (
        await session.execute(select(User.id, User.email).where(User.id.in_([uuid.UUID(i) for i in ids])))
    ).all()
    return {str(i): e for i, e in rows}


def _audit_detail(row: AuditLog, emails: dict[str, str]) -> AuditDetail:
    meta = {k: str(v) for k, v in (row.metadata_ or {}).items()}
    ip_hash = meta.pop("ip_hash", None)
    m = _UUID.search(row.actor)
    return AuditDetail(
        id=row.id,
        actor=row.actor,
        actor_email=emails.get(m.group(0)) if m else None,
        action=row.action,
        target=row.target,
        at=row.at,
        changes=meta,
        ip_hash=ip_hash,
    )


async def _recent_errors(session: AsyncSession, limit: int = 10) -> list[ErrorItem]:
    rows = (
        await session.execute(
            select(Scan.target_url, Scan.error, Scan.finished_at, Scan.created_at)
            .where(Scan.status == "failed")
            .order_by(Scan.created_at.desc())
            .limit(limit)
        )
    ).all()
    items = [
        ErrorItem(source="scan", at=finished or created, title=error or "internal", detail=target)
        for target, error, finished, created in rows
    ]
    for row in await health_svc.latest(session):
        if row.status in ("degraded", "down"):
            items.append(
                ErrorItem(
                    source="module",
                    at=row.checked_at,
                    title=f"{row.module_key}: {row.status}",
                    detail=f"error rate {row.error_rate:.0%}",
                )
            )
    return items


async def sentry_issues(redis: Redis) -> SentryView:
    """Unresolved Sentry issues of the last 24 h, when a read-only API token is configured.

    The API container has no internet route of its own (ADR-0006): Sentry's API is reached only
    through SENTRY_API_PROXY (the egress proxy, with sentry.io on its allowlist). Without a token
    the panel says so; nothing else depends on it. Cached for 60 s.
    """
    s = get_settings()
    if s.sentry_api_token is None or not s.sentry_org or not s.sentry_project:
        return SentryView(configured=False)
    cache_key = "gh:admin:sentry-issues"
    try:
        cached = await redis.get(cache_key)
        if cached:
            return SentryView.model_validate_json(cached)
    except Exception:
        log.warning("sentry_cache_unavailable", exc_info=True)
    url = f"{s.sentry_api_url.rstrip('/')}/api/0/projects/{s.sentry_org}/{s.sentry_project}/issues/"
    try:
        async with httpx.AsyncClient(timeout=4.0, proxy=s.sentry_api_proxy or None) as client:
            r = await client.get(
                url,
                params={"query": "is:unresolved", "statsPeriod": "24h", "limit": "10", "sort": "freq"},
                headers={"Authorization": f"Bearer {s.sentry_api_token.get_secret_value()}"},
            )
        r.raise_for_status()
        issues = [
            ErrorItem(
                source="sentry",
                at=datetime.fromisoformat(str(i.get("lastSeen")).replace("Z", "+00:00"))
                if i.get("lastSeen")
                else None,
                title=str(i.get("title", ""))[:200],
                detail=str(i.get("culprit", ""))[:200],
                count=int(i.get("count", 0) or 0),
                link=str(i.get("permalink", "")) or None,
            )
            for i in r.json()
        ]
        view = SentryView(configured=True, issues=issues)
    except (httpx.HTTPError, ValueError, TypeError):
        log.warning("sentry_issues_unavailable", exc_info=True)
        return SentryView(configured=True, error="unavailable")
    try:
        await redis.set(cache_key, view.model_dump_json(), ex=60)
    except Exception:
        log.warning("sentry_cache_unavailable", exc_info=True)
    return view


# --------------------------------------------------------------------------------------------
# overview
# --------------------------------------------------------------------------------------------


class OverviewView(BaseModel):
    scans: ScanCounts
    findings: SeverityCounts
    modules: list[ModuleRate]
    health: health_svc.LiveHealth
    queue: QueueView
    scanners: list[ScannerInfo]
    recent_audit: list[AuditDetail]
    recent_errors: list[ErrorItem]
    sentry: SentryView


async def overview(claims: SessionClaims, redis: Redis) -> OverviewView:
    async with db_session(_ctx(claims)) as session:
        scans = await _scan_counts(session)
        findings = await _open_findings(session)
        rates = await _module_rates(session)
        rows = await audit.list_recent(session, 10)
        emails = await _emails(session, [r.actor for r in rows])
        recent_audit = [_audit_detail(r, emails) for r in rows]
        errors = await _recent_errors(session)
    return OverviewView(
        scans=scans,
        findings=findings,
        modules=rates,
        health=await health_svc.live_status(redis),
        queue=await _queue(redis),
        scanners=await _scanners(redis),
        recent_audit=recent_audit,
        recent_errors=errors,
        sentry=await sentry_issues(redis),
    )


# --------------------------------------------------------------------------------------------
# module centre
# --------------------------------------------------------------------------------------------


class TriageStats(BaseModel):
    groups: int = 0  # distinct findings (fingerprints) seen in production
    verified: int = 0
    accepted: int = 0
    false_positive: int = 0
    resolved: int = 0
    false_positive_rate: float | None = None  # false_positive / triaged (verified + false_positive)


class ModuleStats(BaseModel):
    check_id: str
    runs_7d: int
    failed_7d: int
    success_rate_7d: float | None
    triage: TriageStats


async def module_stats(claims: SessionClaims) -> list[ModuleStats]:
    async with db_session(_ctx(claims)) as session:
        rates = {r.check_id: r for r in await _module_rates(session)}
        groups = dict(
            (
                await session.execute(
                    select(Finding.check_id, func.count(func.distinct(Finding.fingerprint))).group_by(
                        Finding.check_id
                    )
                )
            ).all()
        )
        triaged = (
            await session.execute(
                select(FindingTriage.check_id, FindingTriage.status, func.count()).group_by(
                    FindingTriage.check_id, FindingTriage.status
                )
            )
        ).all()
    stats: dict[str, TriageStats] = {}
    for check_id, n in groups.items():
        stats[check_id] = TriageStats(groups=int(n))
    for check_id, status, n in triaged:
        st = stats.setdefault(check_id, TriageStats())
        setattr(st, status, int(n))
    for st in stats.values():
        judged = st.verified + st.false_positive
        st.false_positive_rate = st.false_positive / judged if judged else None
    out = []
    for check_id in sorted(set(stats) | set(rates)):
        r = rates.get(check_id)
        out.append(
            ModuleStats(
                check_id=check_id,
                runs_7d=r.runs if r else 0,
                failed_7d=r.failed if r else 0,
                success_rate_7d=r.success_rate if r else None,
                triage=stats.get(check_id, TriageStats()),
            )
        )
    return out


async def module_changelog(claims: SessionClaims, key: str, limit: int = 50) -> list[AuditDetail]:
    async with db_session(_ctx(claims)) as session:
        if (await session.execute(select(Module.id).where(Module.key == key))).scalar_one_or_none() is None:
            raise NotFoundError("module_not_found", "Unknown module.")
        rows = await audit.list_recent(session, limit, action="module.", target=key)
        emails = await _emails(session, [r.actor for r in rows])
    return [_audit_detail(r, emails) for r in rows]


# --------------------------------------------------------------------------------------------
# scan orchestration
# --------------------------------------------------------------------------------------------


class OwnershipProof(BaseModel):
    kind: Literal["project", "one_time", "none"]
    method: str | None = None
    verified_at: datetime | None = None


class AdminScanView(BaseModel):
    id: uuid.UUID
    target_url: str
    lifecycle: Lifecycle
    status: str
    error: str | None
    trigger: str
    kind: Literal["site", "repo"]
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: int | None
    checks: int
    failed_checks: list[str]
    score: int | None
    project_id: uuid.UUID | None
    project_name: str | None
    owner_email: str | None
    ownership: OwnershipProof
    can_cancel: bool
    can_rerun: bool


def _scan_row_view(
    scan: Scan,
    project: Project | None,
    verification: TargetVerification | None,
    owner_email: str | None,
) -> AdminScanView:
    if project is not None:
        proof = OwnershipProof(
            kind="project", method=project.ownership_method, verified_at=project.ownership_verified_at
        )
    elif verification is not None:
        proof = OwnershipProof(
            kind="one_time", method=verification.method, verified_at=verification.verified_at
        )
    else:
        proof = OwnershipProof(kind="none")
    duration = None
    if scan.started_at and scan.finished_at:
        duration = max(0, int((scan.finished_at - scan.started_at).total_seconds()))
    active = scan.status in ("queued", "running")
    return AdminScanView(
        id=scan.id,
        target_url=scan.target_url,
        lifecycle=lifecycle(scan.status, scan.error),
        status=scan.status,
        error=scan.error,
        trigger=scan.trigger,
        kind="repo" if project is not None and project.kind == "repo" else "site",
        created_at=scan.created_at,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        duration_seconds=duration,
        checks=len(scan.checks or []),
        failed_checks=list(scan.failed_checks or []),
        score=scan.score,
        project_id=scan.project_id,
        project_name=project.name if project is not None else None,
        owner_email=owner_email,
        ownership=proof,
        can_cancel=active,
        can_rerun=project is not None and not active,
    )


def _lifecycle_filter(stage: str) -> Any:
    match stage:
        case "completed":
            return Scan.status == "done"
        case "timed_out":
            return and_(Scan.status == "failed", Scan.error == "timeout")
        case "failed":
            return and_(Scan.status == "failed", func.coalesce(Scan.error, "") != "timeout")
        case _:
            return Scan.status == stage


async def _scan_views(session: AsyncSession, scans: list[Scan]) -> list[AdminScanView]:
    project_ids = {s.project_id for s in scans if s.project_id}
    verification_ids = {s.verification_id for s in scans if s.verification_id}
    user_ids = {s.user_id for s in scans if s.user_id}
    projects = (
        {
            p.id: p
            for p in (await session.execute(select(Project).where(Project.id.in_(project_ids)))).scalars()
        }
        if project_ids
        else {}
    )
    verifications = (
        {
            v.id: v
            for v in (
                await session.execute(
                    select(TargetVerification).where(TargetVerification.id.in_(verification_ids))
                )
            ).scalars()
        }
        if verification_ids
        else {}
    )
    emails = (
        dict((await session.execute(select(User.id, User.email).where(User.id.in_(user_ids)))).all())
        if user_ids
        else {}
    )
    return [
        _scan_row_view(
            s,
            projects.get(s.project_id) if s.project_id else None,
            verifications.get(s.verification_id) if s.verification_id else None,
            emails.get(s.user_id) if s.user_id else None,
        )
        for s in scans
    ]


async def list_scans(
    claims: SessionClaims, *, stage: str | None, limit: int, offset: int
) -> list[AdminScanView]:
    async with db_session(_ctx(claims)) as session:
        stmt = select(Scan)
        if stage:
            stmt = stmt.where(_lifecycle_filter(stage))
        scans = list(
            (
                await session.execute(stmt.order_by(Scan.created_at.desc()).limit(limit).offset(offset))
            ).scalars()
        )
        return await _scan_views(session, scans)


async def get_scan(claims: SessionClaims, scan_id: uuid.UUID) -> AdminScanView:
    async with db_session(_ctx(claims)) as session:
        scan = await scan_repo.get(session, scan_id)
        if scan is None:
            raise NotFoundError("scan_not_found", "Scan not found.")
        return (await _scan_views(session, [scan]))[0]


async def cancel_scan(claims: SessionClaims, redis: Redis, scan_id: uuid.UUID) -> AdminScanView:
    """Queued or running -> cancelled. The scanner skips the job if it has not started it (cancel
    key), an active scan stops at its next request (its kill key), and the API ignores the scan's
    later events. Audited as scan.cancel."""
    async with db_session(DbContext.system()) as session:
        scan = await scan_repo.get(session, scan_id, for_update=True)
        if scan is None:
            raise NotFoundError("scan_not_found", "Scan not found.")
        if scan.status not in ("queued", "running"):
            raise ConflictError("scan_not_active", "Only a queued or running scan can be cancelled.")
        # stop first (cheap and idempotent), then record
        await redis.set(SCAN_CANCEL_PREFIX + str(scan_id), "1", ex=CANCEL_KEY_TTL_SECONDS)
        await kill.engage(redis, scan_id)
        previous = scan.status
        scan.status = "cancelled"
        scan.error = "cancelled"
        scan.finished_at = datetime.now(UTC)
        await audit.record(
            session,
            actor=_actor(claims),
            action="scan.cancel",
            target=str(scan_id),
            metadata={"from": previous},
        )
    return await get_scan(claims, scan_id)


async def rerun_scan(claims: SessionClaims, redis: Redis, scan_id: uuid.UUID) -> AdminScanView:
    """Start a new scan of the same project, through the same rules as the owner's rescan
    (ownership proof re-checked when stale, one active scan per project). The project belongs to a
    customer, whose rows only the owner or the system context may write (RLS WITH CHECK): it runs in
    the system context after the admin check, audited with the admin as actor."""
    async with db_session(_ctx(claims)) as session:
        scan = await scan_repo.get(session, scan_id)
        if scan is None:
            raise NotFoundError("scan_not_found", "Scan not found.")
        project_id = scan.project_id
    if project_id is None:
        raise UnprocessableError("scan_has_no_project", "Only scans of a saved project can be run again.")
    new = await start_project_scan(
        redis, project_id=project_id, ctx=DbContext.system(), actor=_actor(claims), trigger="manual"
    )
    async with db_session(_ctx(claims)) as session:
        await audit.record(
            session,
            actor=_actor(claims),
            action="scan.rerun",
            target=str(new.id),
            metadata={"from_scan": str(scan_id)},
        )
    return await get_scan(claims, new.id)


class ActiveTestingState(BaseModel):
    approved: bool  # API: ACTIVE_TESTING_APPROVED (founder checkpoint, ADR-0008 §8)
    scanner_switch: Literal["on", "off", "unknown"]  # SCANNER_ACTIVE_ENABLED as scanners report it
    global_kill: bool
    modules_on: list[str]
    oob_configured: bool
    effective: Literal["off", "on"]  # on only when every switch allows it and the kill is released


class OrchestrationView(BaseModel):
    counts: ScanCounts
    queue: QueueView
    scanners: list[ScannerInfo]
    passive_limits: dict[str, float] | None  # from the scanners' reports (first scanner)
    active_limits: dict[str, float]
    active: ActiveTestingState


async def orchestration(claims: SessionClaims, redis: Redis) -> OrchestrationView:
    async with db_session(_ctx(claims)) as session:
        counts = await _scan_counts(session)
        modules_on = list(
            (
                await session.execute(
                    select(Module.key).where(
                        Module.key.in_(ACTIVE_CHECK_IDS), Module.enabled_global.is_(True)
                    )
                )
            ).scalars()
        )
    scanners = await _scanners(redis)
    try:
        global_kill = (await kill.state(redis, None)).engaged
    except Exception:
        global_kill = True  # unreadable means killed (fail closed, ADR-0008 §3)
    switch: Literal["on", "off", "unknown"] = "unknown"
    if scanners:
        switch = "on" if any(s.active_enabled for s in scanners) else "off"
    approved = get_settings().active_testing_approved
    effective: Literal["off", "on"] = (
        "on" if approved and switch == "on" and modules_on and not global_kill else "off"
    )
    passive = None
    if scanners:
        s0 = scanners[0]
        passive = {
            "requests_per_second_per_host": s0.host_rps,
            "burst": s0.host_burst,
            "requests_per_scan": s0.max_requests_per_scan,
            "request_timeout_seconds": s0.request_timeout_ms / 1000,
            "workers": s0.workers,
            "checks_in_parallel": s0.check_concurrency,
        }
    return OrchestrationView(
        counts=counts,
        queue=await _queue(redis),
        scanners=scanners,
        passive_limits=passive,
        active_limits=ACTIVE_LIMITS,
        active=ActiveTestingState(
            approved=approved,
            scanner_switch=switch,
            global_kill=global_kill,
            modules_on=sorted(modules_on),
            oob_configured=any(s.active_oob for s in scanners),
            effective=effective,
        ),
    )


# --------------------------------------------------------------------------------------------
# findings & risk
# --------------------------------------------------------------------------------------------


class FindingGroupView(BaseModel):
    fingerprint: str
    check_id: str
    finding_key: str
    severity: str
    title: str
    target_url: str
    location: str | None
    occurrences: int  # how many scans reported it (deduplicated by fingerprint)
    first_seen: datetime
    last_seen: datetime
    latest_scan_id: uuid.UUID
    latest_status: str  # the finding row's own status in its latest scan (open | fixed | ignored)
    triage: Literal["new", "verified", "accepted", "false_positive", "resolved"]
    triage_note: str
    triage_updated_at: datetime | None
    classification: Classification
    score_points: int  # what one occurrence takes off the 0-100 score (its severity weight)


_SEVERITY_RANK = case(
    {s: i for i, s in enumerate(SEVERITY_ORDER)},
    value=Finding.severity,
    else_=len(SEVERITY_ORDER),
)


async def list_findings(
    claims: SessionClaims,
    *,
    severity: str | None,
    check_id: str | None,
    triage: str | None,
    limit: int,
    offset: int,
    locale: str,
) -> list[FindingGroupView]:
    grouped = (
        select(
            Finding.fingerprint,
            Finding.check_id,
            Finding.finding_key,
            Finding.severity,
            func.count().label("occurrences"),
            func.min(Finding.created_at).label("first_seen"),
            func.max(Finding.created_at).label("last_seen"),
            func.min(_SEVERITY_RANK).label("rank"),
        )
        .group_by(Finding.fingerprint, Finding.check_id, Finding.finding_key, Finding.severity)
        .subquery()
    )
    stmt = select(grouped, FindingTriage).outerjoin(
        FindingTriage, FindingTriage.fingerprint == grouped.c.fingerprint
    )
    if severity:
        stmt = stmt.where(grouped.c.severity == severity)
    if check_id:
        stmt = stmt.where(grouped.c.check_id == check_id)
    if triage == "new":
        stmt = stmt.where(FindingTriage.fingerprint.is_(None))
    elif triage:
        stmt = stmt.where(FindingTriage.status == triage)
    stmt = stmt.order_by(grouped.c.rank, grouped.c.last_seen.desc()).limit(limit).offset(offset)
    async with db_session(_ctx(claims)) as session:
        rows = (await session.execute(stmt)).all()
        prints = [r.fingerprint for r in rows]
        latest: dict[str, tuple[Finding, Scan, str | None]] = {}
        if prints:
            newest = (
                select(Finding.id)
                .where(Finding.fingerprint.in_(prints))
                .distinct(Finding.fingerprint)
                .order_by(Finding.fingerprint, Finding.created_at.desc())
            )
            for found, found_scan, found_location in (
                await session.execute(
                    select(Finding, Scan, Evidence.location)
                    .join(Scan, Scan.id == Finding.scan_id)
                    .outerjoin(Evidence, Evidence.id == Finding.evidence_ref)
                    .where(Finding.id.in_(newest))
                )
            ).all():
                latest[found.fingerprint] = (found, found_scan, found_location)
    out = []
    for r in rows:
        if r.fingerprint not in latest:
            continue
        finding, scan, location = latest[r.fingerprint]
        tri: FindingTriage | None = r.FindingTriage
        out.append(
            FindingGroupView(
                fingerprint=r.fingerprint,
                check_id=r.check_id,
                finding_key=r.finding_key,
                severity=r.severity,
                title=render_finding(r.check_id, r.finding_key, dict(finding.params or {}), locale).title,
                target_url=scan.target_url,
                location=location,
                occurrences=int(r.occurrences),
                first_seen=r.first_seen,
                last_seen=r.last_seen,
                latest_scan_id=scan.id,
                latest_status=finding.status,
                triage=tri.status if tri else "new",
                triage_note=tri.note if tri else "",
                triage_updated_at=tri.updated_at if tri else None,
                classification=classify(r.check_id, r.finding_key, dict(finding.params or {})),
                score_points=SEVERITY_WEIGHTS.get(r.severity, 0),
            )
        )
    return out


class TriageView(BaseModel):
    fingerprint: str
    status: TriageStatus
    note: str
    updated_at: datetime


async def set_triage(claims: SessionClaims, fingerprint: str, status: str, note: str) -> TriageView:
    if status not in TRIAGE_STATUSES:
        raise UnprocessableError("invalid_triage_status", "Unknown triage status.")
    note = note.strip()[:500]
    async with db_session(_ctx(claims)) as session:
        check_id = (
            await session.execute(select(Finding.check_id).where(Finding.fingerprint == fingerprint).limit(1))
        ).scalar_one_or_none()
        if check_id is None:
            raise NotFoundError("finding_not_found", "Finding not found.")
        row = await session.get(FindingTriage, fingerprint)
        previous = row.status if row else "new"
        now = datetime.now(UTC)
        if row is None:
            row = FindingTriage(
                fingerprint=fingerprint,
                check_id=check_id,
                status=status,
                note=note,
                updated_by=claims.user_id,
                updated_at=now,
            )
            session.add(row)
        else:
            row.status, row.note, row.updated_by, row.updated_at = status, note, claims.user_id, now
        await session.flush()
        await audit.record(
            session,
            actor=_actor(claims),
            action="finding.triage",
            target=fingerprint,
            metadata={"from": previous, "to": status, "check_id": check_id, "note_chars": str(len(note))},
        )
        return TriageView(fingerprint=fingerprint, status=status, note=note, updated_at=now)


class RiskContribution(BaseModel):
    severity: str
    count: int
    weight: int
    points: int


class RiskFinding(BaseModel):
    check_id: str
    finding_key: str
    severity: str
    title: str
    points: int
    cwe: list[str]


class RiskView(BaseModel):
    scan_id: uuid.UUID
    target_url: str
    score: int | None
    recomputed: int  # the formula applied to the findings below (equals score for a completed scan)
    formula: str
    weights: dict[str, int]
    contributions: list[RiskContribution]
    findings: list[RiskFinding]
    capped_at_zero: bool


async def scan_risk(claims: SessionClaims, scan_id: uuid.UUID, locale: str) -> RiskView:
    """The score explained: 100 minus a fixed weight per finding, by severity, never below 0
    (findings/scoring.py). Same findings give the same score."""
    async with db_session(_ctx(claims)) as session:
        scan = await scan_repo.get(session, scan_id)
        if scan is None:
            raise NotFoundError("scan_not_found", "Scan not found.")
        findings = list((await session.execute(select(Finding).where(Finding.scan_id == scan_id))).scalars())
    severities = [f.severity for f in findings]
    contributions = []
    for sev in SEVERITY_ORDER:
        n = severities.count(sev)
        if n:
            w = SEVERITY_WEIGHTS[sev]
            contributions.append(RiskContribution(severity=sev, count=n, weight=w, points=n * w))
    total = sum(c.points for c in contributions)
    ordered = sorted(findings, key=lambda f: (SEVERITY_ORDER.index(f.severity), f.check_id))
    return RiskView(
        scan_id=scan.id,
        target_url=scan.target_url,
        score=scan.score,
        recomputed=compute_score(severities),
        formula="score = max(0, 100 - sum(weight[severity] for each finding))",
        weights=dict(SEVERITY_WEIGHTS),
        contributions=contributions,
        findings=[
            RiskFinding(
                check_id=f.check_id,
                finding_key=f.finding_key,
                severity=f.severity,
                title=render_finding(f.check_id, f.finding_key, dict(f.params or {}), locale).title,
                points=SEVERITY_WEIGHTS.get(f.severity, 0),
                cwe=classify(f.check_id, f.finding_key).cwe,
            )
            for f in ordered
        ],
        capped_at_zero=total > 100,
    )


# --------------------------------------------------------------------------------------------
# audit & monitoring
# --------------------------------------------------------------------------------------------


async def audit_log(
    claims: SessionClaims,
    *,
    limit: int,
    offset: int,
    action: str | None,
    actor: str | None,
    target: str | None,
) -> list[AuditDetail]:
    async with db_session(_ctx(claims)) as session:
        rows = await audit.list_recent(session, limit, offset, action=action, actor=actor, target=target)
        emails = await _emails(session, [r.actor for r in rows])
    return [_audit_detail(r, emails) for r in rows]


class MonitoringView(BaseModel):
    health: health_svc.LiveHealth
    components: list[health_svc.HealthRow]
    queue: QueueView
    scanners: list[ScannerInfo]
    recent_errors: list[ErrorItem]
    sentry: SentryView


async def monitoring(claims: SessionClaims, redis: Redis) -> MonitoringView:
    async with db_session(_ctx(claims)) as session:
        components = await health_svc.latest(session)
        errors = await _recent_errors(session, limit=20)
    return MonitoringView(
        health=await health_svc.live_status(redis),
        components=components,
        queue=await _queue(redis),
        scanners=await _scanners(redis),
        recent_errors=errors,
        sentry=await sentry_issues(redis),
    )
