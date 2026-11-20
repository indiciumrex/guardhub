"""Alert jobs (docs/architecture.md §8.4): change alerts after a project scan, "monitoring paused"
alerts, and test notifications. Runs in `api-jobs` under the 'system' DB context.

Only CHANGES alert. The first done scan is a baseline (no alert); nothing changed → nothing sent.
Each change alert is one `notifications` row per (scan, channel), created once and locked while
sending, so retries and duplicate jobs never send twice; attempts are bounded (`MAX_ATTEMPTS`).
Messages carry title + severity + one-line summary only, never evidence.
"Monitoring paused" and test alerts have no scan: they are `notification_events` rows, one per
(job id, channel), with the same send-once locking. All of them form the user's alert history.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from guardhub_api.alerts import render
from guardhub_api.alerts import repository as alerts_repo
from guardhub_api.alerts.delivery import DeliveryError, EmailNotConfiguredError, send_email, send_slack
from guardhub_api.alerts.repository import Prefs
from guardhub_api.alerts.service import decrypt_webhook
from guardhub_api.auth import repository as user_repo
from guardhub_api.config import get_settings
from guardhub_api.db.models import Notification, NotificationEvent
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.projects import repository as project_repo
from guardhub_api.scans import compare
from guardhub_api.scans import repository as scan_repo
from guardhub_api.scans.diff import DiffFinding, DiffResult
from guardhub_api.scans.schemas import DiffItem

log = logging.getLogger("guardhub.alerts")

MAX_ATTEMPTS = 3

Outcome = Literal["not_applicable", "baseline", "no_change", "done", "retry"]
EventKind = Literal["monitoring_paused", "test"]


@dataclass(frozen=True, slots=True)
class AlertPlan:
    kind: Literal["change", "fixed"]
    new: tuple[DiffFinding, ...]
    regressed: tuple[DiffFinding, ...]
    fixed: tuple[DiffFinding, ...]


def plan_alert(result: DiffResult, prefs: Prefs) -> AlertPlan | None:
    """Decide what (if anything) to send, from the diff and the user's `notify_*` switches."""
    if result.is_baseline:
        return None
    new = result.new if prefs.notify_new else ()
    regressed = result.regressed if prefs.notify_regression else ()
    if new or regressed:
        return AlertPlan("change", new, regressed, result.fixed)
    if result.fixed and prefs.notify_fixed:
        return AlertPlan("fixed", (), (), result.fixed)
    return None


def enabled_channels(prefs: Prefs) -> list[str]:
    channels = ["email"] if prefs.email_enabled else []
    if prefs.slack_webhook_enc is not None:
        channels.append("slack")
    return channels


def compare_link(project_id: uuid.UUID, scan_id: uuid.UUID) -> str:
    base = get_settings().public_base_url.rstrip("/")
    return f"{base}/account/projects/{project_id}/compare/{scan_id}"


def project_link(project_id: uuid.UUID) -> str:
    return f"{get_settings().public_base_url.rstrip('/')}/account/projects/{project_id}"


def _alert_items(items: Sequence[DiffItem]) -> list[render.AlertItem]:
    return [render.AlertItem(severity=i.severity, title=i.title, summary=i.summary) for i in items]


def build_scan_message(
    plan: AlertPlan,
    *,
    locale: str,
    project_name: str,
    target: str,
    link: str,
    score: int | None,
    base_score: int | None,
) -> render.AlertMessage:
    if plan.kind == "change":
        return render.change_alert(
            locale,
            project=project_name,
            target=target,
            link=link,
            new=_alert_items(compare.render_items(plan.new, locale)),
            regressed=_alert_items(compare.render_items(plan.regressed, locale)),
            fixed_count=len(plan.fixed),
            score=score,
            base_score=base_score,
        )
    return render.fixed_alert(
        locale,
        project=project_name,
        target=target,
        link=link,
        fixed=_alert_items(compare.render_items(plan.fixed, locale)),
        score=score,
        base_score=base_score,
    )


@dataclass(frozen=True, slots=True)
class _Recipient:
    user_id: uuid.UUID
    email: str
    locale: str
    slack_webhook_enc: str | None


async def _send(channel: str, recipient: _Recipient, message: render.AlertMessage) -> None:
    if channel == "email":
        await send_email(recipient.email, message)
        return
    if recipient.slack_webhook_enc is None:
        raise DeliveryError("slack_not_configured", retryable=False)
    try:
        url = decrypt_webhook(recipient.user_id, recipient.slack_webhook_enc)
    except Exception as exc:  # tampered/foreign ciphertext (AAD mismatch) or a rotated key
        raise DeliveryError("slack_webhook_undecryptable", retryable=False) from exc
    await send_slack(url, message)


# ---- change alerts ----


async def notify_scan(scan_id: uuid.UUID, *, final_try: bool) -> Outcome:
    async with db_session(DbContext.system()) as session:
        scan = await scan_repo.get(session, scan_id)
        if scan is None or scan.status != "done" or scan.project_id is None or scan.user_id is None:
            return "not_applicable"
        project = await project_repo.get(session, scan.project_id)
        user = await user_repo.by_id(session, scan.user_id)
        if project is None or user is None or project.user_id != user.id:
            return "not_applicable"
        base = await compare.resolve_base(session, scan, None)
        if base is None:
            return "baseline"
        result = await compare.diff_scans(session, scan, base)
        prefs = alerts_repo.prefs_of(await alerts_repo.get_settings(session, user.id))
        plan = plan_alert(result, prefs)
        channels = enabled_channels(prefs)
        if plan is None or not channels:
            return "no_change" if plan is None else "not_applicable"
        message = build_scan_message(
            plan,
            locale=user.locale,
            project_name=project.name,
            target=project.target_url,
            link=compare_link(project.id, scan.id),
            score=scan.score,
            base_score=base.score,
        )
        for channel in channels:
            await alerts_repo.ensure_notification(
                session,
                user_id=user.id,
                project_id=project.id,
                scan_id=scan.id,
                channel=channel,
                new_count=len(plan.new),
                regression_count=len(plan.regressed),
                fixed_count=len(plan.fixed),
            )
        recipient = _Recipient(user.id, user.email, user.locale, prefs.slack_webhook_enc)
    retry = False
    for channel in channels:
        retry |= await _deliver_scan_alert(scan_id, channel, recipient, message, final_try=final_try)
    return "retry" if retry else "done"


async def _attempt(
    row: Notification | NotificationEvent,
    channel: str,
    recipient: _Recipient,
    message: render.AlertMessage,
    *,
    final_try: bool,
    ref: dict[str, str],
) -> bool:
    """One delivery attempt for a LOCKED pending row; records the outcome on it.

    Returns True when a later retry should run (the row then stays 'pending')."""
    row.attempts += 1
    try:
        await _send(channel, recipient, message)
    except EmailNotConfiguredError:
        row.status, row.error = "skipped", "email_not_configured"
        return False
    except DeliveryError as exc:
        row.error = exc.code
        if exc.retryable and row.attempts < MAX_ATTEMPTS and not final_try:
            log.warning("alert_retry", extra={**ref, "channel": channel, "error": exc.code})
            return True
        row.status = "failed"
        log.error("alert_failed", extra={**ref, "channel": channel, "error": exc.code})
        return False
    row.status, row.error, row.sent_at = "sent", None, datetime.now(UTC)
    log.info("alert_sent", extra={**ref, "channel": channel})
    return False


async def _deliver_scan_alert(
    scan_id: uuid.UUID, channel: str, recipient: _Recipient, message: render.AlertMessage, *, final_try: bool
) -> bool:
    """Send one (scan, channel) alert at most once. Returns True when a later retry should run."""
    async with db_session(DbContext.system()) as session:
        row = await alerts_repo.lock_notification(session, scan_id, channel)
        if row is None or row.status != "pending":
            return False  # being sent by another worker right now, or already final
        return await _attempt(
            row, channel, recipient, message, final_try=final_try, ref={"scan_id": str(scan_id)}
        )


async def _deliver_event(
    *,
    kind: EventKind,
    dedupe_key: str,
    project_id: uuid.UUID | None,
    channels: Sequence[str],
    recipient: _Recipient,
    message: render.AlertMessage,
    final_try: bool,
) -> Outcome:
    """Record + send a non-scan alert once per (event, channel): it shows up in the history."""
    async with db_session(DbContext.system()) as session:
        for channel in channels:
            await alerts_repo.ensure_event(
                session,
                user_id=recipient.user_id,
                project_id=project_id,
                kind=kind,
                dedupe_key=dedupe_key,
                channel=channel,
            )
    retry = False
    for channel in channels:
        async with db_session(DbContext.system()) as session:
            row = await alerts_repo.lock_event(session, dedupe_key, channel)
            if row is None or row.status != "pending":
                continue
            retry |= await _attempt(
                row, channel, recipient, message, final_try=final_try, ref={"kind": kind, "event": dedupe_key}
            )
    return "retry" if retry else "done"


# ---- monitoring paused ----


async def notify_paused(project_id: uuid.UUID, *, job_id: str, final_try: bool) -> Outcome:
    if not job_id:
        raise ValueError("notify_paused needs the job's unique id (it de-duplicates the alert)")
    async with db_session(DbContext.system()) as session:
        project = await project_repo.get(session, project_id)
        if project is None or project.schedule_paused_reason is None:
            return "not_applicable"  # deleted, or the user already resumed monitoring
        user = await user_repo.by_id(session, project.user_id)
        if user is None:
            return "not_applicable"
        prefs = alerts_repo.prefs_of(await alerts_repo.get_settings(session, user.id))
        recipient = _Recipient(user.id, user.email, user.locale, prefs.slack_webhook_enc)
        message = render.paused_alert(
            user.locale, project=project.name, target=project.target_url, link=project_link(project.id)
        )
    channels = enabled_channels(prefs)
    if not channels:
        return "not_applicable"
    return await _deliver_event(
        kind="monitoring_paused",
        dedupe_key=job_id,
        project_id=project_id,
        channels=channels,
        recipient=recipient,
        message=message,
        final_try=final_try,
    )


# ---- test notification ----


async def send_test(user_id: uuid.UUID, channel: str, *, job_id: str) -> Outcome:
    """A test message, recorded in the history as kind 'test' (filtered out by default)."""
    if not job_id:
        raise ValueError("send_test needs the job's unique id")
    async with db_session(DbContext.system()) as session:
        user = await user_repo.by_id(session, user_id)
        if user is None:
            return "not_applicable"
        prefs = alerts_repo.prefs_of(await alerts_repo.get_settings(session, user_id))
    recipient = _Recipient(user.id, user.email, user.locale, prefs.slack_webhook_enc)
    return await _deliver_event(
        kind="test",
        dedupe_key=f"test:{job_id}",
        project_id=None,
        channels=[channel],
        recipient=recipient,
        message=render.channel_check_alert(user.locale),
        final_try=True,  # a test is tried once; the user can simply send another
    )
