"""Scheduled monitoring: `enqueue_due_scans` (docs/architecture.md §8.2), run by Arq every 5 min.

1. Claim (one short transaction): lock due projects with FOR UPDATE SKIP LOCKED (at most
   SCHEDULER_BATCH), count scheduled scans already queued/running (SCHEDULER_MAX_INFLIGHT cap,
   shared host §7.2). A project with a scan in progress just moves to its next slot; the others
   are claimed while there is room (their next slot is set now) or stay due for the next tick.
2. Start each claimed project's scan through `projects.scanning.start_project_scan`, the SAME
   path as a manual rescan: verified, re-proven when older than 30 days, trusted domains must be
   active; `trigger='scheduled'`, enqueued with `scans.queue.enqueue_scan`.
3. Proof gone → pause the schedule (`ownership_lost`), audit `project.schedule_paused`, and queue
   the `paused` alert. Temporary problems (scanner/queue down, site unreachable) retry within an hour.
The scanner's do-no-harm envelope (§3) applies unchanged: this only decides WHEN to scan.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from redis.asyncio import Redis

from guardhub_api.common import audit
from guardhub_api.common.errors import (
    ConflictError,
    GuardHubError,
    NotFoundError,
    ServiceUnavailableError,
    UnprocessableError,
)
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.jobs import client as jobs
from guardhub_api.platform import service as platform
from guardhub_api.projects import repository as project_repo
from guardhub_api.projects.scanning import start_project_scan
from guardhub_api.projects.schedule import next_run_after
from guardhub_api.scans import repository as scan_repo

log = logging.getLogger("guardhub.scheduler")

ACTOR = "system:scheduler"
RETRY_AFTER_TRANSIENT = timedelta(hours=1)
PAUSE_REASON = "ownership_lost"


@dataclass
class SchedulerReport:
    started: list[uuid.UUID] = field(default_factory=list)
    moved_on: list[uuid.UUID] = field(default_factory=list)
    paused: list[uuid.UUID] = field(default_factory=list)
    deferred: list[uuid.UUID] = field(default_factory=list)
    waiting_for_capacity: int = 0

    def as_log(self) -> dict[str, int]:
        return {
            "started": len(self.started),
            "moved_on": len(self.moved_on),
            "paused": len(self.paused),
            "deferred": len(self.deferred),
            "waiting_for_capacity": self.waiting_for_capacity,
        }


def proof_is_gone(error: UnprocessableError) -> bool:
    """A definitive "no proof" (pause) vs. "could not check right now" (retry later)."""
    if error.code in ("trusted_domain_inactive", "repo_access_lost"):
        return True
    if error.code == "ownership_not_verified":
        reason = (error.details or {}).get("reason")
        return reason is None or reason == "not_found"
    return False


async def claim_due(now: datetime, report: SchedulerReport) -> list[uuid.UUID]:
    claimed: list[uuid.UUID] = []
    if await platform.flag("maintenance.enabled") or not await platform.flag("flags.scheduled_scans"):
        return claimed  # paused by an admin: due projects stay due and run once it is lifted
    max_inflight = await platform.int_value("scheduler.max_inflight")
    batch = await platform.int_value("scheduler.batch")
    async with db_session(DbContext.system()) as session:
        room = max(0, max_inflight - await scan_repo.count_inflight_scheduled(session))
        for project in await project_repo.lock_due(session, now, batch):
            assert project.next_scan_at is not None
            if await scan_repo.has_active(session, project.id):
                project.next_scan_at = next_run_after(project.next_scan_at, project.scan_frequency, now)
                report.moved_on.append(project.id)
            elif room > 0:
                room -= 1
                project.next_scan_at = next_run_after(project.next_scan_at, project.scan_frequency, now)
                claimed.append(project.id)
            else:
                report.waiting_for_capacity += 1
    return claimed


async def pause_schedule(project_id: uuid.UUID, now: datetime) -> bool:
    """Pause once (audited) and queue the `paused` alert in the same transaction's lifetime."""
    async with db_session(DbContext.system()) as session:
        project = await project_repo.get(session, project_id, for_update=True)
        if project is None or project.scan_frequency == "off" or project.schedule_paused_reason is not None:
            return False
        project.schedule_paused_reason = PAUSE_REASON
        await audit.record(
            session,
            actor=ACTOR,
            action="project.schedule_paused",
            target=str(project_id),
            metadata={"reason": PAUSE_REASON},
        )
        # Queued before the commit: if the commit fails the job finds the project not paused and
        # sends nothing; if queuing fails the pause rolls back and the next tick tries again.
        await jobs.enqueue_notify_paused(project_id, now)
    return True


async def _defer(project_id: uuid.UUID, now: datetime) -> None:
    async with db_session(DbContext.system()) as session:
        project = await project_repo.get(session, project_id, for_update=True)
        if project is not None and project.next_scan_at is not None:
            project.next_scan_at = min(project.next_scan_at, now + RETRY_AFTER_TRANSIENT)


async def _still_scheduled(project_id: uuid.UUID) -> bool:
    async with db_session(DbContext.system()) as session:
        project = await project_repo.get(session, project_id)
        return (
            project is not None and project.scan_frequency != "off" and project.schedule_paused_reason is None
        )


async def run_one(redis: Redis, project_id: uuid.UUID, now: datetime, report: SchedulerReport) -> None:
    if not await _still_scheduled(project_id):  # turned off or deleted since it was claimed
        return
    try:
        await start_project_scan(
            redis, project_id=project_id, ctx=DbContext.system(), actor=ACTOR, trigger="scheduled"
        )
        report.started.append(project_id)
    except (ConflictError, NotFoundError):
        report.moved_on.append(project_id)  # a manual scan started meanwhile, or the project is gone
    except UnprocessableError as exc:
        if proof_is_gone(exc):
            if await pause_schedule(project_id, now):
                report.paused.append(project_id)
        else:
            log.warning("scheduled_scan_deferred", extra={"project_id": str(project_id), "code": exc.code})
            await _defer(project_id, now)
            report.deferred.append(project_id)
    except (ServiceUnavailableError, GuardHubError) as exc:
        log.warning("scheduled_scan_deferred", extra={"project_id": str(project_id), "code": exc.code})
        await _defer(project_id, now)
        report.deferred.append(project_id)
    except Exception:  # one broken project must not stop the rest of the tick
        log.exception("scheduled_scan_error", extra={"project_id": str(project_id)})
        await _defer(project_id, now)
        report.deferred.append(project_id)


async def enqueue_due_scans(redis: Redis, now: datetime | None = None) -> SchedulerReport:
    now = now or datetime.now(UTC)
    report = SchedulerReport()
    for project_id in await claim_due(now, report):
        await run_one(redis, project_id, now, report)
    log.info("scheduler_tick", extra=report.as_log())
    return report
