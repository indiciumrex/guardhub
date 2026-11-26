"""The admin reports (Prompt 2 §3): one function per report, each returns a Table.

All reports cover the last `days` days (7, 30 or 90) and run as admin (RLS: privileged).
Customer e-mail addresses and target hosts are always masked (reports/export.py).
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime, timedelta
from typing import Literal

from sqlalchemy import Date, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.db.models import Finding, FindingTriage, Project, Scan, User
from guardhub_api.reports.export import Cell, Table, mask_email, mask_host

ReportKind = Literal["platform", "modules", "scans", "findings", "customers", "risk_trend"]
KINDS: tuple[ReportKind, ...] = ("platform", "modules", "scans", "findings", "customers", "risk_trend")
DAYS = (7, 30, 90)
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_ROWS = 5000


def _since(days: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


async def platform(session: AsyncSession, days: int) -> Table:
    """One row per day: scans by outcome, findings by severity, new users."""
    since = _since(days)
    day = cast(func.timezone("UTC", Scan.created_at), Date)
    scans = (
        await session.execute(
            select(day, Scan.status, func.count()).where(Scan.created_at >= since).group_by(day, Scan.status)
        )
    ).all()
    fday = cast(func.timezone("UTC", Finding.created_at), Date)
    findings = (
        await session.execute(
            select(fday, Finding.severity, func.count())
            .where(Finding.created_at >= since)
            .group_by(fday, Finding.severity)
        )
    ).all()
    uday = cast(func.timezone("UTC", User.created_at), Date)
    users = (
        await session.execute(select(uday, func.count()).where(User.created_at >= since).group_by(uday))
    ).all()

    by_day: dict[date, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for d, status, n in scans:
        by_day[d]["scans"] += n
        by_day[d][f"scans_{status}"] += n
    for d, sev, n in findings:
        by_day[d][sev] += n
    for d, n in users:
        by_day[d]["new_users"] += n
    columns = ["date", "scans", "scans_done", "scans_failed", "scans_cancelled", *SEVERITIES, "new_users"]
    today = datetime.now(UTC).date()
    rows: list[list[Cell]] = []
    for i in range(days, -1, -1):
        d = today - timedelta(days=i)
        v = by_day.get(d, {})
        rows.append([d.isoformat(), *[v.get(c, 0) for c in columns[1:]]])
    return Table("platform", columns, rows, days)


async def modules(session: AsyncSession, days: int) -> Table:
    """One row per check: runs, could-not-run, findings by severity, false positives (triage)."""
    since = _since(days)
    runs: dict[str, int] = defaultdict(int)
    failed: dict[str, int] = defaultdict(int)
    for checks, failed_checks in (
        await session.execute(
            select(Scan.checks, Scan.failed_checks).where(Scan.created_at >= since, Scan.status == "done")
        )
    ).all():
        for c in checks or []:
            runs[c] += 1
        for c in failed_checks or []:
            failed[c] += 1
    sev: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for check, s, n in (
        await session.execute(
            select(Finding.check_id, Finding.severity, func.count())
            .where(Finding.created_at >= since)
            .group_by(Finding.check_id, Finding.severity)
        )
    ).all():
        sev[check][s] += n
    fps = dict(
        (
            await session.execute(
                select(FindingTriage.check_id, func.count())
                .where(FindingTriage.status == "false_positive")
                .group_by(FindingTriage.check_id)
            )
        ).all()
    )
    columns = ["check_id", "runs", "could_not_run", *SEVERITIES, "false_positive_groups"]
    rows: list[list[Cell]] = []
    for check in sorted(set(runs) | set(sev)):
        rows.append(
            [
                check,
                runs.get(check, 0),
                failed.get(check, 0),
                *[sev[check].get(s, 0) for s in SEVERITIES],
                int(fps.get(check, 0)),
            ]
        )
    return Table("modules", columns, rows, days)


async def scans(session: AsyncSession, days: int) -> Table:
    since = _since(days)
    result = (
        await session.execute(
            select(
                Scan.created_at,
                Scan.id,
                Scan.trigger,
                Scan.status,
                Scan.score,
                Scan.target_url,
                Scan.checks,
                Scan.failed_checks,
            )
            .where(Scan.created_at >= since)
            .order_by(Scan.created_at.desc())
            .limit(MAX_ROWS + 1)
        )
    ).all()
    columns = ["created_at", "scan_id", "trigger", "status", "score", "target", "checks", "could_not_run"]
    rows: list[list[Cell]] = [
        [at.isoformat(), str(sid), trig, st, score, mask_host(target), len(chk or []), len(fc or [])]
        for at, sid, trig, st, score, target, chk, fc in result[:MAX_ROWS]
    ]
    return Table("scans", columns, rows, days, truncated=len(result) > MAX_ROWS)


async def findings(session: AsyncSession, days: int) -> Table:
    """One row per check and severity: findings, distinct groups, and the admin's triage."""
    since = _since(days)
    base = (
        await session.execute(
            select(
                Finding.check_id,
                Finding.severity,
                func.count(),
                func.count(func.distinct(Finding.fingerprint)),
            )
            .where(Finding.created_at >= since)
            .group_by(Finding.check_id, Finding.severity)
        )
    ).all()
    triage: dict[tuple[str, str], dict[str, int]] = defaultdict(lambda: defaultdict(int))
    sub = (
        select(Finding.check_id, Finding.severity, Finding.fingerprint)
        .where(Finding.created_at >= since)
        .distinct()
        .subquery()
    )
    for check, s, status, n in (
        await session.execute(
            select(sub.c.check_id, sub.c.severity, FindingTriage.status, func.count())
            .join(FindingTriage, FindingTriage.fingerprint == sub.c.fingerprint)
            .group_by(sub.c.check_id, sub.c.severity, FindingTriage.status)
        )
    ).all():
        triage[(check, s)][status] += n
    order = {s: i for i, s in enumerate(SEVERITIES)}
    columns = [
        "check_id",
        "severity",
        "findings",
        "groups",
        "verified",
        "accepted",
        "false_positive",
        "resolved",
    ]
    rows: list[list[Cell]] = []
    for check, s, n, groups in sorted(base, key=lambda r: (order.get(r[1], 9), r[0])):
        t = triage[(check, s)]
        rows.append([check, s, n, groups, t["verified"], t["accepted"], t["false_positive"], t["resolved"]])
    return Table("findings", columns, rows, days)


async def customers(session: AsyncSession, days: int) -> Table:
    """One row per customer account (masked): projects, scans and serious findings in the window."""
    since = _since(days)
    users = (
        await session.execute(
            select(User.id, User.email, User.created_at)
            .where(User.role == "user")
            .order_by(User.created_at.desc())
            .limit(MAX_ROWS + 1)
        )
    ).all()
    projects = dict(
        (await session.execute(select(Project.user_id, func.count()).group_by(Project.user_id))).all()
    )
    scan_rows = (
        await session.execute(
            select(Scan.user_id, func.count(), func.max(Scan.created_at))
            .where(Scan.created_at >= since, Scan.user_id.is_not(None))
            .group_by(Scan.user_id)
        )
    ).all()
    scans_by = {u: (n, last) for u, n, last in scan_rows}
    serious = dict(
        (
            await session.execute(
                select(Scan.user_id, func.count())
                .join(Finding, Finding.scan_id == Scan.id)
                .where(
                    Finding.created_at >= since,
                    Finding.severity.in_(("critical", "high")),
                    Scan.user_id.is_not(None),
                )
                .group_by(Scan.user_id)
            )
        ).all()
    )
    columns = ["customer", "joined", "projects", "scans", "critical_or_high", "last_scan"]
    rows: list[list[Cell]] = []
    for uid, email, joined in users[:MAX_ROWS]:
        n, last = scans_by.get(uid, (0, None))
        rows.append(
            [
                mask_email(email),
                joined.date().isoformat(),
                int(projects.get(uid, 0)),
                n,
                int(serious.get(uid, 0)),
                last.isoformat() if last else None,
            ]
        )
    return Table("customers", columns, rows, days, truncated=len(users) > MAX_ROWS)


async def risk_trend(session: AsyncSession, days: int) -> Table:
    """One row per week: completed scans, their average score, critical and high findings."""
    since = _since(days)
    week = func.date_trunc("week", func.timezone("UTC", Scan.created_at))
    scored = (
        await session.execute(
            select(week, func.count(), func.avg(Scan.score))
            .where(Scan.created_at >= since, Scan.status == "done")
            .group_by(week)
        )
    ).all()
    fweek = func.date_trunc("week", func.timezone("UTC", Finding.created_at))
    sev: dict[object, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for w, s, n in (
        await session.execute(
            select(fweek, Finding.severity, func.count())
            .where(Finding.created_at >= since, Finding.severity.in_(("critical", "high")))
            .group_by(fweek, Finding.severity)
        )
    ).all():
        sev[w.date() if hasattr(w, "date") else w][s] += n
    by_week = {(w.date() if hasattr(w, "date") else w): (n, avg) for w, n, avg in scored}
    columns = ["week", "completed_scans", "average_score", "critical", "high"]
    rows: list[list[Cell]] = []
    for w in sorted(set(by_week) | set(sev), key=str):
        n, avg = by_week.get(w, (0, None))
        rows.append(
            [str(w), n, round(float(avg), 1) if avg is not None else None, sev[w]["critical"], sev[w]["high"]]
        )
    return Table("risk_trend", columns, rows, days)


BUILDERS: dict[str, Callable[[AsyncSession, int], Awaitable[Table]]] = {
    "platform": platform,
    "modules": modules,
    "scans": scans,
    "findings": findings,
    "customers": customers,
    "risk_trend": risk_trend,
}
