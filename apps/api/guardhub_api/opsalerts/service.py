"""Operational alerts for admins (Admin Panel, Prompt 2 §2).

Four rules, evaluated every minute by api-jobs (`evaluate`):
- critical_finding: critical findings recorded in the window >= threshold;
- scan_failures: scans that failed in the window >= threshold;
- worker_offline: no scanner reading the job stream for >= threshold minutes;
- api_errors: API 5xx responses in the window >= threshold (opsalerts/counters.py).

While a condition holds there is exactly one unresolved alert for its kind (opened once, then
updated); when it clears, the alert resolves on its own. Alerts are always recorded in-app.
E-mail goes to every admin once when an alert opens, unless the rule is muted or its e-mail is
off. An alert nobody acknowledged within `escalate_after_minutes` sends one escalation e-mail.
Every admin action (acknowledge, resolve, rule change, mute) is audited.

The alert mails carry counts and a link only: no customer targets, findings or secrets.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.alerts import render
from guardhub_api.alerts.delivery import send_email
from guardhub_api.alerts.render import AlertMessage
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit
from guardhub_api.common.errors import NotFoundError, UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.db.models import Finding, OpsAlert, OpsAlertRule, Scan, User
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.opsalerts.counters import errors_in_window
from guardhub_api.scans.queue import scanner_alive

log = logging.getLogger(__name__)

Kind = Literal["critical_finding", "scan_failures", "worker_offline", "api_errors"]
KINDS: tuple[Kind, ...] = ("critical_finding", "scan_failures", "worker_offline", "api_errors")
SCANNER_DOWN_KEY = "gh:ops:scanner-down-since"
MUTE_CHOICES = (0, 60, 240, 1440)  # minutes; 0 = unmute
RECENT_LIMIT = 50


# ---- measuring ----


async def _measure(redis: Redis, rule: OpsAlertRule, now: datetime) -> int:
    since = now - timedelta(minutes=rule.window_minutes)
    if rule.kind == "critical_finding":
        async with db_session(DbContext.system()) as session:
            stmt = (
                select(func.count())
                .select_from(Finding)
                .where(Finding.severity == "critical", Finding.created_at >= since)
            )
            return int((await session.execute(stmt)).scalar_one())
    if rule.kind == "scan_failures":
        async with db_session(DbContext.system()) as session:
            stmt = (
                select(func.count())
                .select_from(Scan)
                .where(Scan.status == "failed", Scan.finished_at >= since)
            )
            return int((await session.execute(stmt)).scalar_one())
    if rule.kind == "worker_offline":
        return await _scanner_down_minutes(redis, now)
    return await errors_in_window(redis, rule.window_minutes, now.timestamp())


async def _scanner_down_minutes(redis: Redis, now: datetime) -> int:
    """Minutes since the scanner was last seen reading jobs (0 while it is alive)."""
    if await scanner_alive(redis):
        await redis.delete(SCANNER_DOWN_KEY)
        return 0
    await redis.set(SCANNER_DOWN_KEY, str(int(now.timestamp())), nx=True, ex=7 * 86400)
    since = int(await redis.get(SCANNER_DOWN_KEY) or now.timestamp())
    return max(0, int((now.timestamp() - since) // 60))


# ---- evaluating ----


@dataclass(frozen=True, slots=True)
class Mail:
    alert_id: uuid.UUID
    kind: str
    value: int
    threshold: int
    escalation: bool


def _muted(rule: OpsAlertRule, now: datetime) -> bool:
    return rule.muted_until is not None and rule.muted_until > now


async def evaluate(redis: Redis, now: datetime | None = None) -> dict[str, int]:
    """One pass over every rule. Returns counters for the job log."""
    now = now or datetime.now(UTC)
    report = {"opened": 0, "resolved": 0, "mails": 0}
    async with db_session(DbContext.system()) as session:
        rules = (await session.execute(select(OpsAlertRule))).scalars().all()
    mails: list[Mail] = []
    for rule in rules:
        try:
            value = await _measure(redis, rule, now)
        except Exception:  # one broken measurement must not stop the other rules
            log.exception("ops_alert_measure_failed", extra={"kind": rule.kind})
            continue
        mails += await _apply(rule, value, now, report)
    for mail in mails:
        report["mails"] += await _send(mail)
    return report


async def _apply(rule: OpsAlertRule, value: int, now: datetime, report: dict[str, int]) -> list[Mail]:
    breach = rule.enabled and value >= rule.threshold
    mails: list[Mail] = []
    async with db_session(DbContext.system()) as session:
        current = (
            await session.execute(
                select(OpsAlert)
                .where(OpsAlert.kind == rule.kind, OpsAlert.status != "resolved")
                .with_for_update()
            )
        ).scalar_one_or_none()
        if not breach:
            if current is not None:
                current.status, current.resolved_at = "resolved", now
                report["resolved"] += 1
                await audit.record(
                    session,
                    actor="system:ops-alerts",
                    action="ops_alert.resolved",
                    target=str(current.id),
                    metadata={"kind": rule.kind, "auto": "true"},
                )
            return mails
        if current is None:
            current = OpsAlert(
                kind=rule.kind,
                status="open",
                value=value,
                threshold=rule.threshold,
                detail={},
                opened_at=now,
                last_seen_at=now,
            )
            session.add(current)
            await session.flush()
            report["opened"] += 1
            await audit.record(
                session,
                actor="system:ops-alerts",
                action="ops_alert.opened",
                target=str(current.id),
                metadata={"kind": rule.kind, "value": str(value)},
            )
        else:
            current.value, current.threshold, current.last_seen_at = value, rule.threshold, now
        if rule.email and not _muted(rule, now):
            if current.emailed_at is None:
                current.emailed_at = now  # claimed: one opening mail per alert, even if sending fails
                mails.append(Mail(current.id, rule.kind, value, rule.threshold, escalation=False))
            due = rule.escalate_after_minutes is not None and now - current.opened_at >= timedelta(
                minutes=rule.escalate_after_minutes
            )
            if current.status == "open" and current.escalated_at is None and due:
                current.escalated_at = now
                mails.append(Mail(current.id, rule.kind, value, rule.threshold, escalation=True))
    return mails


# ---- e-mail ----


def build_mail(mail: Mail, locale: str) -> AlertMessage:
    """Counts and a link only (texts: packages/shared/i18n/<locale>/notifications.json, opsAlert)."""
    loc = "tr" if locale.startswith("tr") else "en"
    label = render.text(loc, f"opsAlert.kind.{mail.kind}")
    link = f"{get_settings().public_base_url.rstrip('/')}/admin/alerts"
    subject = render.text(
        loc, "opsAlert.subjectEscalated" if mail.escalation else "opsAlert.subject", label=label
    )
    body = render.text(
        loc, "opsAlert.body", label=label, value=str(mail.value), threshold=str(mail.threshold)
    )
    return AlertMessage(subject=render.one_line(subject), text=f"{body}\n\n{link}\n", html="", slack="")


async def _send(mail: Mail) -> int:
    async with db_session(DbContext.system()) as session:
        admins = (await session.execute(select(User.email, User.locale).where(User.role == "admin"))).all()
    sent = 0
    for email, locale in admins:
        try:
            await send_email(email, build_mail(mail, locale or "en"))
            sent += 1
        except Exception as exc:  # recorded on the alert; never retried in a loop
            log.warning("ops_alert_mail_failed", extra={"kind": mail.kind, "error": type(exc).__name__})
            async with db_session(DbContext.system()) as session:
                alert = await session.get(OpsAlert, mail.alert_id)
                if alert is not None:
                    alert.detail = {**alert.detail, "email_error": type(exc).__name__}
    return sent


# ---- the admin's screen ----


class RuleView(BaseModel):
    kind: str
    enabled: bool
    threshold: int
    window_minutes: int
    email: bool
    muted_until: datetime | None
    escalate_after_minutes: int | None
    updated_at: datetime


class AlertView(BaseModel):
    id: uuid.UUID
    kind: str
    status: str
    value: int
    threshold: int
    opened_at: datetime
    last_seen_at: datetime
    acknowledged_at: datetime | None
    resolved_at: datetime | None
    resolved_automatically: bool
    emailed_at: datetime | None
    escalated_at: datetime | None
    email_error: str | None


class AlertsView(BaseModel):
    open: list[AlertView]
    recent: list[AlertView]
    rules: list[RuleView]
    email_configured: bool
    admin_recipients: int


class UpdateRule(BaseModel):
    enabled: bool
    threshold: int = Field(ge=1, le=1000)
    window_minutes: int = Field(ge=5, le=1440)
    email: bool
    escalate_after_minutes: int | None = Field(default=None, ge=5, le=1440)


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="admin", user_id=claims.user_id)


def _rule_view(r: OpsAlertRule) -> RuleView:
    return RuleView(
        kind=r.kind,
        enabled=r.enabled,
        threshold=r.threshold,
        window_minutes=r.window_minutes,
        email=r.email,
        muted_until=r.muted_until,
        escalate_after_minutes=r.escalate_after_minutes,
        updated_at=r.updated_at,
    )


def _alert_view(a: OpsAlert) -> AlertView:
    err = a.detail.get("email_error") if isinstance(a.detail, dict) else None
    return AlertView(
        id=a.id,
        kind=a.kind,
        status=a.status,
        value=a.value,
        threshold=a.threshold,
        opened_at=a.opened_at,
        last_seen_at=a.last_seen_at,
        acknowledged_at=a.acknowledged_at,
        resolved_at=a.resolved_at,
        resolved_automatically=a.resolved_at is not None and a.resolved_by is None,
        emailed_at=a.emailed_at,
        escalated_at=a.escalated_at,
        email_error=str(err) if err else None,
    )


async def view(claims: SessionClaims) -> AlertsView:
    async with db_session(_ctx(claims)) as session:
        rules = (await session.execute(select(OpsAlertRule))).scalars().all()
        open_ = (
            (
                await session.execute(
                    select(OpsAlert).where(OpsAlert.status != "resolved").order_by(OpsAlert.opened_at.desc())
                )
            )
            .scalars()
            .all()
        )
        recent = (
            (await session.execute(select(OpsAlert).order_by(OpsAlert.opened_at.desc()).limit(RECENT_LIMIT)))
            .scalars()
            .all()
        )
        admins = int(
            (
                await session.execute(select(func.count()).select_from(User).where(User.role == "admin"))
            ).scalar_one()
        )
    order: dict[str, int] = {k: i for i, k in enumerate(KINDS)}
    return AlertsView(
        open=[_alert_view(a) for a in open_],
        recent=[_alert_view(a) for a in recent],
        rules=[_rule_view(r) for r in sorted(rules, key=lambda r: order.get(r.kind, 99))],
        email_configured=bool(get_settings().smtp_host.strip()),
        admin_recipients=admins,
    )


async def _alert_action(
    claims: SessionClaims, alert_id: uuid.UUID, action: Literal["ack", "resolve"]
) -> AlertView:
    now = datetime.now(UTC)
    async with db_session(_ctx(claims)) as session:
        alert = await session.get(OpsAlert, alert_id, with_for_update=True)
        if alert is None:
            raise NotFoundError("alert_not_found", "This alert does not exist.")
        if alert.status == "resolved":
            raise UnprocessableError("alert_resolved", "This alert is already resolved.")
        if action == "ack":
            alert.status, alert.acknowledged_at, alert.acknowledged_by = "acknowledged", now, claims.user_id
        else:
            alert.status, alert.resolved_at, alert.resolved_by = "resolved", now, claims.user_id
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="ops_alert.acknowledged" if action == "ack" else "ops_alert.resolved",
            target=str(alert.id),
            metadata={"kind": alert.kind},
        )
        await session.flush()
        return _alert_view(alert)


async def acknowledge(claims: SessionClaims, alert_id: uuid.UUID) -> AlertView:
    return await _alert_action(claims, alert_id, "ack")


async def resolve(claims: SessionClaims, alert_id: uuid.UUID) -> AlertView:
    return await _alert_action(claims, alert_id, "resolve")


async def _rule(session: AsyncSession, kind: str) -> OpsAlertRule:
    rule = await session.get(OpsAlertRule, kind, with_for_update=True)
    if rule is None:
        raise NotFoundError("alert_rule_not_found", "This alert rule does not exist.")
    return rule


async def update_rule(claims: SessionClaims, kind: str, body: UpdateRule) -> RuleView:
    async with db_session(_ctx(claims)) as session:
        rule = await _rule(session, kind)
        before = _rule_view(rule).model_dump(mode="json", exclude={"updated_at", "muted_until"})
        rule.enabled, rule.threshold, rule.window_minutes = body.enabled, body.threshold, body.window_minutes
        rule.email, rule.escalate_after_minutes = body.email, body.escalate_after_minutes
        rule.updated_by, rule.updated_at = claims.user_id, datetime.now(UTC)
        after = _rule_view(rule).model_dump(mode="json", exclude={"updated_at", "muted_until"})
        changes = {k: f"{before[k]} -> {after[k]}" for k in after if before[k] != after[k]}
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="ops_alert_rule.changed",
            target=kind,
            metadata=changes,
        )
        await session.flush()
        return _rule_view(rule)


async def mute(claims: SessionClaims, kind: str, minutes: int) -> RuleView:
    if minutes not in MUTE_CHOICES:
        raise UnprocessableError("mute_invalid", "Mute for 1 hour, 4 hours or 24 hours, or unmute.")
    now = datetime.now(UTC)
    async with db_session(_ctx(claims)) as session:
        rule = await _rule(session, kind)
        rule.muted_until = now + timedelta(minutes=minutes) if minutes else None
        rule.updated_by, rule.updated_at = claims.user_id, now
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="ops_alert_rule.muted" if minutes else "ops_alert_rule.unmuted",
            target=kind,
            metadata={"minutes": str(minutes)},
        )
        await session.flush()
        return _rule_view(rule)
