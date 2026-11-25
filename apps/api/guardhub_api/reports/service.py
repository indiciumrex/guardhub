"""Admin reports (Admin Panel, Prompt 2 §3): build, export (audited) and scheduled summaries.

Exports contain customer data in masked form only. Every CSV / XLSX export is audited
(report.exported, with kind, format and days). Scheduled summaries (weekly on Mondays, monthly
on the 1st, 06:05 UTC) e-mail the admins counts and a link, never rows.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel
from sqlalchemy import select

from guardhub_api.alerts import render
from guardhub_api.alerts.delivery import send_email
from guardhub_api.alerts.render import AlertMessage
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit
from guardhub_api.common.errors import UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.db.models import ReportSchedule, User
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.reports import builders
from guardhub_api.reports.export import Cell, Table, to_csv, to_xlsx

log = logging.getLogger(__name__)
Format = Literal["csv", "xlsx"]
Frequency = Literal["weekly", "monthly"]
MEDIA = {
    "csv": "text/csv; charset=utf-8",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
PREVIEW_ROWS = 200


class ReportView(BaseModel):
    kind: str
    days: int
    columns: list[str]
    rows: list[list[Cell]]
    total_rows: int
    truncated: bool
    masked: bool
    generated_at: datetime


class ScheduleView(BaseModel):
    frequency: str
    enabled: bool
    last_sent_at: datetime | None
    updated_at: datetime


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="admin", user_id=claims.user_id)


def _check(kind: str, days: int) -> None:
    if kind not in builders.BUILDERS:
        raise UnprocessableError("report_unknown", "This report does not exist.")
    if days not in builders.DAYS:
        raise UnprocessableError("report_days_invalid", "Choose 7, 30 or 90 days.")


async def build(claims: SessionClaims | None, kind: str, days: int) -> Table:
    _check(kind, days)
    ctx = _ctx(claims) if claims else DbContext.system()
    async with db_session(ctx) as session:
        return await builders.BUILDERS[kind](session, days)


async def preview(claims: SessionClaims, kind: str, days: int) -> ReportView:
    t = await build(claims, kind, days)
    return ReportView(
        kind=t.kind,
        days=t.days,
        columns=t.columns,
        rows=t.rows[:PREVIEW_ROWS],
        total_rows=len(t.rows),
        truncated=t.truncated or len(t.rows) > PREVIEW_ROWS,
        masked=True,
        generated_at=t.generated_at,
    )


async def export(claims: SessionClaims, kind: str, days: int, fmt: Format) -> tuple[bytes, str, str]:
    """(content, media type, file name). Audited before the file leaves the API."""
    t = await build(claims, kind, days)
    content = to_csv(t) if fmt == "csv" else to_xlsx(t)
    async with db_session(_ctx(claims)) as session:
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="report.exported",
            target=kind,
            metadata={"format": fmt, "days": str(days), "rows": str(len(t.rows))},
        )
    name = f"guardhub-{kind}-{days}d-{t.generated_at:%Y%m%d}.{fmt}"
    return content, MEDIA[fmt], name


# ---- schedules ----


def _schedule_view(s: ReportSchedule) -> ScheduleView:
    return ScheduleView(
        frequency=s.frequency, enabled=s.enabled, last_sent_at=s.last_sent_at, updated_at=s.updated_at
    )


async def schedules(claims: SessionClaims) -> list[ScheduleView]:
    async with db_session(_ctx(claims)) as session:
        rows = (
            (await session.execute(select(ReportSchedule).order_by(ReportSchedule.frequency.desc())))
            .scalars()
            .all()
        )
        return [_schedule_view(s) for s in rows]


async def set_schedule(claims: SessionClaims, frequency: str, enabled: bool) -> ScheduleView:
    async with db_session(_ctx(claims)) as session:
        s = await session.get(ReportSchedule, frequency, with_for_update=True)
        if s is None:
            raise UnprocessableError("report_schedule_unknown", "Weekly or monthly only.")
        s.enabled, s.updated_by, s.updated_at = enabled, claims.user_id, datetime.now(UTC)
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="report.schedule_changed",
            target=frequency,
            metadata={"enabled": str(enabled).lower()},
        )
        await session.flush()
        return _schedule_view(s)


def due(frequency: str, last_sent_at: datetime | None, now: datetime) -> bool:
    """Weekly on Mondays, monthly on the 1st; never twice for the same period."""
    if frequency == "weekly":
        return now.weekday() == 0 and (last_sent_at is None or now - last_sent_at > timedelta(days=6))
    return now.day == 1 and (last_sent_at is None or now - last_sent_at > timedelta(days=27))


def summary(table: Table) -> dict[str, int]:
    idx = {c: i for i, c in enumerate(table.columns)}

    def total(col: str) -> int:
        return sum(int(r[idx[col]] or 0) for r in table.rows)

    return {k: total(k) for k in ("scans", "scans_failed", "critical", "high", "new_users")}


def build_mail(frequency: str, totals: dict[str, int], locale: str) -> AlertMessage:
    loc = "tr" if locale.startswith("tr") else "en"
    link = f"{get_settings().public_base_url.rstrip('/')}/admin/reports"
    subject = render.text(loc, f"reportMail.subject.{frequency}")
    body = render.text(loc, "reportMail.body", **{k: str(v) for k, v in totals.items()})
    return AlertMessage(subject=render.one_line(subject), text=f"{body}\n\n{link}\n", html="", slack="")


async def send_scheduled(now: datetime | None = None) -> dict[str, int]:
    """Daily (api-jobs): e-mail the due summaries to every admin. A failure is logged, not retried."""
    now = now or datetime.now(UTC)
    sent = 0
    async with db_session(DbContext.system()) as session:
        rows = (
            (await session.execute(select(ReportSchedule).where(ReportSchedule.enabled.is_(True))))
            .scalars()
            .all()
        )
        todo = [s.frequency for s in rows if due(s.frequency, s.last_sent_at, now)]
        admins = (await session.execute(select(User.email, User.locale).where(User.role == "admin"))).all()
    for frequency in todo:
        table = await build(None, "platform", 7 if frequency == "weekly" else 30)
        totals = summary(table)
        for email, locale in admins:
            try:
                await send_email(email, build_mail(frequency, totals, locale or "en"))
                sent += 1
            except Exception as exc:
                log.warning("report_mail_failed", extra={"frequency": frequency, "error": type(exc).__name__})
        async with db_session(DbContext.system()) as session:
            s = await session.get(ReportSchedule, frequency)
            if s is not None:
                s.last_sent_at = now
    return {"due": len(todo), "mails": sent}
