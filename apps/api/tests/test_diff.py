"""Diff engine (§8.3), schedule math (§8.2) and alert planning (§8.4): pure logic, no I/O."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from guardhub_api.alerts.notifier import enabled_channels, plan_alert
from guardhub_api.alerts.repository import Prefs
from guardhub_api.projects import schedule
from guardhub_api.scans.diff import (
    DiffFinding,
    ScanSnapshot,
    appeared_fingerprints,
    compute_diff,
    sort_by_severity_then_title,
)
from guardhub_api.scans.ingest import failed_check_ids

CHECKS = ("exposed_env", "security_headers", "tls_cert")


def f(fp: str, check: str = "security_headers", sev: str = "medium") -> DiffFinding:
    return DiffFinding(fingerprint=fp, check_id=check, finding_key=f"k_{fp}", severity=sev)


def snap(
    *findings: DiffFinding, failed: set[str] | None = None, checks: tuple[str, ...] = CHECKS
) -> ScanSnapshot:
    return ScanSnapshot(
        scan_id=uuid.uuid4(), checks=checks, failed_checks=frozenset(failed or set()), findings=findings
    )


def fps(items: tuple[DiffFinding, ...]) -> set[str]:
    return {i.fingerprint for i in items}


def test_baseline_without_previous_scan() -> None:
    s = snap(f("a"), f("b"), failed={"tls_cert"})
    d = compute_diff(s, None)
    assert d.is_baseline and d.base_scan_id is None
    assert d.new == d.regressed == d.fixed == ()
    assert d.unchanged_count == 2
    assert d.compared_checks == ("exposed_env", "security_headers")
    assert d.skipped_checks == ("tls_cert",)
    assert not d.has_changes


def test_new_fixed_and_unchanged() -> None:
    b = snap(f("a"), f("b"))
    s = snap(f("b"), f("c"))
    d = compute_diff(s, b)
    assert d.base_scan_id == b.scan_id
    assert fps(d.new) == {"c"} and fps(d.fixed) == {"a"} and d.regressed == ()
    assert d.unchanged_count == 1
    assert d.compared_checks == CHECKS and d.skipped_checks == ()


def test_identical_scans_have_no_changes() -> None:
    b = snap(f("a"), f("b", "exposed_env", "critical"))
    s = snap(f("a"), f("b", "exposed_env", "critical"))
    d = compute_diff(s, b)
    assert not d.has_changes and d.unchanged_count == 2


def test_regression_needs_presence_before_base() -> None:
    b = snap()
    s = snap(f("x"), f("y"))
    assert appeared_fingerprints(s, b) == {"x", "y"}
    d = compute_diff(s, b, seen_before_base={"x"})
    assert fps(d.regressed) == {"x"} and fps(d.new) == {"y"}


def test_failed_check_in_current_scan_is_not_fixed() -> None:
    b = snap(f("env1", "exposed_env", "critical"), f("h1"))
    s = snap(f("h1"), failed={"exposed_env"})  # the check timed out: its finding is just missing
    d = compute_diff(s, b)
    assert d.fixed == () and d.new == ()
    assert "exposed_env" in d.skipped_checks and "exposed_env" not in d.compared_checks
    assert d.unchanged_count == 1


def test_failed_check_in_base_scan_is_not_new() -> None:
    b = snap(f("h1"), failed={"exposed_env"})
    s = snap(f("env1", "exposed_env", "critical"), f("h1"))
    d = compute_diff(s, b)
    assert d.new == () and d.regressed == ()
    assert "exposed_env" not in appeared_fingerprints(s, b)
    assert d.skipped_checks == ("exposed_env",)


def test_check_missing_from_one_scan_is_skipped() -> None:
    b = snap(f("tls", "tls_cert"), checks=("security_headers", "tls_cert"))
    s = snap(f("env", "exposed_env"), checks=("exposed_env", "security_headers"))
    d = compute_diff(s, b)
    assert d.compared_checks == ("security_headers",)
    assert d.skipped_checks == ("exposed_env", "tls_cert")
    assert not d.has_changes


def test_sorting_by_severity_then_title() -> None:
    items = [("low", "b"), ("critical", "z"), ("low", "A"), ("high", "m")]
    out = sort_by_severity_then_title(items, lambda i: i[0], lambda i: i[1])
    assert out == [("critical", "z"), ("high", "m"), ("low", "A"), ("low", "b")]


def test_failed_check_ids_counts_missing_results_as_failed() -> None:
    results = [
        {"check_id": "exposed_env", "status": "done"},
        {"check_id": "tls_cert", "status": "failed", "error": "timeout"},
        {"check_id": "unknown", "status": "failed"},
        "garbage",
    ]
    assert failed_check_ids(results, list(CHECKS)) == ["security_headers", "tls_cert"]
    assert failed_check_ids(None, ["a"]) == ["a"]


# ---- schedule ----


def test_jitter_is_stable_and_bounded() -> None:
    pid = uuid.UUID("00000000-0000-0000-0000-000000000001")
    assert schedule.jitter(pid) == schedule.jitter(pid)
    for _ in range(200):
        j = schedule.jitter(uuid.uuid4())
        assert timedelta(0) <= j < timedelta(seconds=3600)


def test_first_run_and_next_run() -> None:
    now = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
    pid = uuid.uuid4()
    first = schedule.first_run(pid, "daily", now)
    assert now + timedelta(days=1) <= first < now + timedelta(days=1, hours=1)
    assert schedule.first_run(pid, "weekly", now) - first == timedelta(days=6)
    due = now - timedelta(minutes=3)
    assert schedule.next_run_after(due, "daily", now) == due + timedelta(days=1)
    # long downtime: no catch-up burst, stays on its slot, lands in the future
    old = now - timedelta(days=9, minutes=1)
    nxt = schedule.next_run_after(old, "weekly", now)
    assert nxt > now and (nxt - old) % timedelta(days=7) == timedelta(0)
    with pytest.raises(ValueError):
        schedule.first_run(pid, "off", now)


# ---- alert planning ----


def test_plan_alert_rules() -> None:
    base = snap(f("a"))
    regress = compute_diff(snap(f("a"), f("r")), base, seen_before_base={"r"})
    new = compute_diff(snap(f("a"), f("n")), base)
    fixed = compute_diff(snap(), base)
    same = compute_diff(snap(f("a")), base)

    assert plan_alert(compute_diff(snap(f("a")), None), Prefs()) is None  # baseline
    assert plan_alert(same, Prefs()) is None  # nothing changed: nothing sent
    plan = plan_alert(new, Prefs())
    assert plan is not None and plan.kind == "change" and fps(plan.new) == {"n"}
    plan = plan_alert(regress, Prefs())
    assert plan is not None and plan.kind == "change" and fps(plan.regressed) == {"r"}
    assert plan_alert(regress, Prefs(notify_regression=False)) is None
    assert plan_alert(new, Prefs(notify_new=False)) is None
    plan = plan_alert(fixed, Prefs())
    assert plan is not None and plan.kind == "fixed" and fps(plan.fixed) == {"a"}
    assert plan_alert(fixed, Prefs(notify_fixed=False)) is None


def test_enabled_channels() -> None:
    assert enabled_channels(Prefs()) == ["email"]
    assert enabled_channels(Prefs(email_enabled=False)) == []
    assert enabled_channels(Prefs(slack_webhook_enc="v1.x")) == ["email", "slack"]
