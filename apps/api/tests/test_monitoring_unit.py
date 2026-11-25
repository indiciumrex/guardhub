"""Scheduler selection/caps (§8.2), `against` validation (§8.3) and Arq wiring (§8.1), with the
database replaced by in-memory fakes. The SQL side is covered by tests/integration."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from guardhub_api.common.errors import UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.db.models import Scan
from guardhub_api.jobs import client, scheduler, worker
from guardhub_api.platform import service as platform_service
from guardhub_api.scans import compare

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


@asynccontextmanager
async def fake_session(_ctx: object) -> AsyncIterator[object]:
    yield object()


def _project(minutes_overdue: int = 1) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(), next_scan_at=NOW - timedelta(minutes=minutes_overdue), scan_frequency="daily"
    )


@pytest.fixture
def fake_db(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    state: dict[str, object] = {"projects": [], "busy": set(), "inflight": 0, "limit_seen": None}

    async def lock_due(_s: object, now: datetime, limit: int) -> list[SimpleNamespace]:
        state["limit_seen"] = limit
        return list(state["projects"])[:limit]  # type: ignore[call-overload]

    async def has_active(_s: object, project_id: uuid.UUID) -> bool:
        return project_id in state["busy"]  # type: ignore[operator]

    async def inflight(_s: object) -> int:
        return int(state["inflight"])  # type: ignore[call-overload]

    monkeypatch.setattr(scheduler, "db_session", fake_session)

    async def no_overrides() -> dict[str, object]:
        return {}

    monkeypatch.setattr(platform_service, "_load_overrides", no_overrides)  # defaults: today's behaviour
    platform_service.clear_cache()
    monkeypatch.setattr(scheduler.project_repo, "lock_due", lock_due)
    monkeypatch.setattr(scheduler.scan_repo, "has_active", has_active)
    monkeypatch.setattr(scheduler.scan_repo, "count_inflight_scheduled", inflight)
    return state


async def test_claim_respects_inflight_cap_and_moves_busy_projects(
    fake_db: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "scheduler_max_inflight", 2)
    projects = [_project(30), _project(20), _project(10), _project(5)]
    fake_db["projects"], fake_db["busy"], fake_db["inflight"] = projects, {projects[0].id}, 1
    report = scheduler.SchedulerReport()
    claimed = await scheduler.claim_due(NOW, report)
    # room = 2 - 1 in flight = 1: the busy one moves on, one is claimed, two wait for capacity
    assert claimed == [projects[1].id]
    assert report.moved_on == [projects[0].id] and report.waiting_for_capacity == 2
    for p in (projects[0], projects[1]):
        assert p.next_scan_at > NOW and p.next_scan_at - NOW < timedelta(days=1)
    assert projects[2].next_scan_at < NOW and projects[3].next_scan_at < NOW  # still due


async def test_claim_respects_batch_and_full_capacity(
    fake_db: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "scheduler_batch", 3)
    monkeypatch.setattr(get_settings(), "scheduler_max_inflight", 10)
    fake_db["projects"] = [_project(i + 1) for i in range(6)]
    report = scheduler.SchedulerReport()
    assert len(await scheduler.claim_due(NOW, report)) == 3
    assert fake_db["limit_seen"] == 3

    monkeypatch.setattr(get_settings(), "scheduler_max_inflight", 2)
    fake_db["inflight"] = 5  # more in flight than allowed (e.g. after lowering the cap)
    fake_db["projects"] = [_project(), _project()]
    report = scheduler.SchedulerReport()
    assert await scheduler.claim_due(NOW, report) == []
    assert report.waiting_for_capacity == 2


@pytest.mark.parametrize(
    ("code", "details", "gone"),
    [
        ("ownership_not_verified", {"reason": "not_found"}, True),
        ("ownership_not_verified", None, True),  # never verified / no proof
        ("ownership_not_verified", {"reason": "timeout"}, False),
        ("ownership_not_verified", {"reason": "target_unreachable"}, False),
        ("ownership_not_verified", {"reason": "target_blocked"}, False),
        ("trusted_domain_inactive", None, True),
        ("no_checks_enabled", None, False),
    ],
)
def test_proof_is_gone(code: str, details: dict[str, str] | None, gone: bool) -> None:
    assert scheduler.proof_is_gone(UnprocessableError(code, "m", details)) is gone


# ---- `against` validation ----


def _scan(project: uuid.UUID, user: uuid.UUID, status: str = "done", minutes_ago: int = 10) -> Scan:
    return Scan(
        id=uuid.uuid4(),
        project_id=project,
        user_id=user,
        status=status,
        created_at=NOW - timedelta(minutes=minutes_ago),
        checks=[],
        failed_checks=[],
    )


async def test_against_must_be_an_earlier_done_scan_of_the_same_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, user = uuid.uuid4(), uuid.uuid4()
    current = _scan(project, user, minutes_ago=1)
    good = _scan(project, user, minutes_ago=30)
    candidates = {
        "good": good,
        "self": current,
        "other_project": _scan(uuid.uuid4(), user, minutes_ago=30),
        "other_user": _scan(project, uuid.uuid4(), minutes_ago=30),
        "not_done": _scan(project, user, status="failed", minutes_ago=30),
        "later": _scan(project, user, minutes_ago=0),
    }
    by_id = {s.id: s for s in candidates.values()}

    async def get(_s: object, scan_id: uuid.UUID, **_: object) -> Scan | None:
        return by_id.get(scan_id)

    async def previous_done(_s: object, project_id: uuid.UUID, before: datetime) -> Scan:
        assert project_id == project and before == current.created_at
        return good

    monkeypatch.setattr(compare.repository, "get", get)
    monkeypatch.setattr(compare.repository, "previous_done", previous_done)
    session = object()
    assert await compare.resolve_base(session, current, None) is good  # type: ignore[arg-type]
    assert await compare.resolve_base(session, current, good.id) is good  # type: ignore[arg-type]
    for name in ("self", "other_project", "other_user", "not_done", "later"):
        with pytest.raises(UnprocessableError) as exc:
            await compare.resolve_base(session, current, candidates[name].id)  # type: ignore[arg-type]
        assert exc.value.code == "invalid_comparison", name
    with pytest.raises(UnprocessableError):
        await compare.resolve_base(session, current, uuid.uuid4())  # type: ignore[arg-type]


# ---- Arq wiring ----


def test_worker_registration() -> None:
    names = {f.name for f in worker.FUNCTIONS}
    assert names == {client.NOTIFY_SCAN, client.NOTIFY_PAUSED, client.SEND_TEST_NOTIFICATION}
    notify = next(f for f in worker.FUNCTIONS if f.name == client.NOTIFY_SCAN)
    assert notify.max_tries == 3
    tick, recheck, purge = worker.CRON_JOBS
    assert tick.name == "cron:enqueue_due_scans" and tick.unique and not tick.run_at_startup
    assert tick.minute == set(range(0, 60, 5))
    # ADR-0003: trusted domains are re-proven once a day, one run across all workers/colours
    assert recheck.name == "cron:recheck_trusted_domains" and recheck.unique and not recheck.run_at_startup
    assert (recheck.hour, recheck.minute) == ({4}, {10})
    # ADR-0008 §7: the active request log is purged after 30 days, once a day
    assert purge.name == "cron:purge_active_request_log" and purge.unique and not purge.run_at_startup
    assert (purge.hour, purge.minute) == ({4}, {40})
    assert worker.WorkerSettings.job_serializer is client.serialize_job or callable(
        worker.WorkerSettings.job_serializer
    )


def test_retry_backoff_and_json_jobs() -> None:
    assert [worker.retry_delay_seconds(t) for t in (1, 2, 3)] == [30, 120, 480]
    raw = client.serialize_job({"f": "notify_scan", "a": ["x"], "k": {}, "t": None, "et": 1})
    assert raw.startswith(b"{") and client.deserialize_job(raw)["a"] == ["x"]
    with pytest.raises(ValueError):
        client.deserialize_job(b"[1]")
    with pytest.raises(ValueError):
        client.deserialize_job(b"\x80\x04K\x01.")  # a pickle is never accepted
