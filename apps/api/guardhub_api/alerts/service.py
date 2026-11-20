"""Notification settings for the signed-in user (docs/architecture.md §8.4). Router-agnostic.

The Slack webhook URL is validated strictly, stored AES-GCM encrypted with AAD = user id (so a
ciphertext copied to another user's row does not decrypt), and never returned or logged. Every
change is audited without the URL. Test notifications are queued for `api-jobs` (the API itself
has no internet access) and limited to 3 per hour per user.
"""

from __future__ import annotations

import uuid

from redis.asyncio import Redis
from redis.exceptions import RedisError

from guardhub_api.alerts import repository
from guardhub_api.alerts.delivery import validate_slack_webhook
from guardhub_api.alerts.schemas import (
    NotificationHistoryItem,
    NotificationSettingsView,
    UpdateNotificationSettings,
)
from guardhub_api.auth import repository as user_repo
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit, ratelimit
from guardhub_api.common.crypto import Keyring
from guardhub_api.common.errors import NotFoundError, ServiceUnavailableError, UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.db.models import Notification, NotificationEvent
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.jobs import client as jobs

TEST_LIMIT_PER_HOUR = 3


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext.for_user(claims.user_id, claims.role)


def _cipher() -> Keyring:
    # The keyring, never a single-key Cipher: during a key rotation, webhooks still under the
    # previous key must keep decrypting (ops/rotate_encryption_key re-encrypts them).
    return get_settings().keyring


def slack_aad(user_id: uuid.UUID) -> bytes:
    return str(user_id).encode()


def encrypt_webhook(user_id: uuid.UUID, url: str) -> str:
    return _cipher().encrypt(url, associated_data=slack_aad(user_id))


def decrypt_webhook(user_id: uuid.UUID, ciphertext: str) -> str:
    return _cipher().decrypt(ciphertext, associated_data=slack_aad(user_id))


async def get_view(claims: SessionClaims) -> NotificationSettingsView:
    async with db_session(_ctx(claims)) as session:
        user = await user_repo.by_id(session, claims.user_id)
        if user is None:
            raise NotFoundError("user_not_found", "Account not found.")
        prefs = repository.prefs_of(await repository.get_settings(session, claims.user_id))
        return NotificationSettingsView(
            email_enabled=prefs.email_enabled,
            notify_new=prefs.notify_new,
            notify_regression=prefs.notify_regression,
            notify_fixed=prefs.notify_fixed,
            slack_configured=prefs.slack_webhook_enc is not None,
            email=user.email,
        )


async def update(claims: SessionClaims, body: UpdateNotificationSettings) -> NotificationSettingsView:
    replace_slack = "slack_webhook_url" in body.model_fields_set
    encrypted: str | None = None
    if replace_slack and body.slack_webhook_url is not None:
        encrypted = encrypt_webhook(claims.user_id, validate_slack_webhook(body.slack_webhook_url))
    flags = {
        "email_enabled": body.email_enabled,
        "notify_new": body.notify_new,
        "notify_regression": body.notify_regression,
        "notify_fixed": body.notify_fixed,
    }
    async with db_session(_ctx(claims)) as session:
        await repository.upsert_settings(
            session, claims.user_id, flags=flags, slack_webhook_enc=encrypted, replace_slack=replace_slack
        )
        slack_change = "kept" if not replace_slack else ("set" if encrypted else "removed")
        await audit.record(
            session,
            actor=f"user:{claims.user_id}",
            action="account.notifications_updated",
            target=str(claims.user_id),
            metadata={**{k: str(v).lower() for k, v in flags.items()}, "slack": slack_change},
        )
    return await get_view(claims)


async def request_test(redis: Redis, claims: SessionClaims, channel: str) -> None:
    await ratelimit.enforce(redis, "notify-test", str(claims.user_id), limit=TEST_LIMIT_PER_HOUR, window=3600)
    if channel == "slack":
        async with db_session(_ctx(claims)) as session:
            prefs = repository.prefs_of(await repository.get_settings(session, claims.user_id))
        if prefs.slack_webhook_enc is None:
            raise UnprocessableError("slack_not_configured", "Add a Slack webhook first.")
    elif not get_settings().smtp_host:
        raise UnprocessableError("email_not_configured", "E-mail alerts are not set up on this server.")
    try:
        await jobs.enqueue_test_notification(claims.user_id, channel)
    except (RedisError, OSError) as exc:
        raise ServiceUnavailableError("queue_unavailable", "Please try again in a moment.") from exc


def _history_item(r: Notification | NotificationEvent) -> NotificationHistoryItem:
    if isinstance(r, Notification):
        return NotificationHistoryItem(
            id=r.id,
            kind="scan_change",
            scan_id=r.scan_id,
            project_id=r.project_id,
            channel=r.channel,
            status=r.status,
            new_count=r.new_count,
            regression_count=r.regression_count,
            fixed_count=r.fixed_count,
            created_at=r.created_at,
            sent_at=r.sent_at,
        )
    return NotificationHistoryItem(
        id=r.id,
        kind=r.kind,
        scan_id=None,
        project_id=r.project_id,
        channel=r.channel,
        status=r.status,
        new_count=0,
        regression_count=0,
        fixed_count=0,
        created_at=r.created_at,
        sent_at=r.sent_at,
    )


async def history(
    claims: SessionClaims, limit: int, show: repository.HistoryFilter = "alerts"
) -> list[NotificationHistoryItem]:
    async with db_session(_ctx(claims)) as session:
        rows = await repository.history(session, claims.user_id, limit, show)
        return [_history_item(r) for r in rows]
