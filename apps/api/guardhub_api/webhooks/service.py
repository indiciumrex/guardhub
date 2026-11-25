"""Signed outgoing webhooks (Admin Panel, Prompt 2 §4).

Events: `scan.completed` (only for scans the webhook's owner owns), `ops_alert.opened` and
`ping`. A fan-out job creates one delivery row per matching webhook (idempotent per event) and
queues its delivery. The payload is built at delivery time and holds ids, status and counts
only; the delivery history keeps status, attempts and a SHA-256 of the body, never the body.
Delivery: SSRF guards and an HMAC signature (webhooks/safety.py), 3 attempts with backoff for
network errors, 429 and 5xx; never for a 4xx or a blocked address.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Literal

import httpx
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit
from guardhub_api.common.crypto import random_token
from guardhub_api.common.errors import NotFoundError, UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.db.models import Finding, OpsAlert, Scan, Webhook, WebhookDelivery
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.jobs import client as jobs
from guardhub_api.webhooks.safety import UnsafeWebhookError, resolve_public, sign, validate_url

log = logging.getLogger(__name__)
Event = Literal["scan.completed", "ops_alert.opened", "ping"]
EVENTS: tuple[Event, ...] = ("scan.completed", "ops_alert.opened", "ping")
TIMEOUT_SECONDS = 10.0
RECENT_DELIVERIES = 20
USER_AGENT = "GuardHub-Webhooks/1.0 (+https://guardhub.dev)"


def _aad(webhook_id: uuid.UUID) -> bytes:
    # The text of the row id, as ops/rotate_encryption_key.py re-encrypts it on key rotation.
    return str(webhook_id).encode()


# ---- the admin's screen ----


class CreateWebhookRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    url: str = Field(min_length=12, max_length=2048)
    events: list[Event] = Field(min_length=1, max_length=len(EVENTS))


class DeliveryView(BaseModel):
    id: uuid.UUID
    event: str
    status: str
    attempts: int
    http_status: int | None
    error: str | None
    created_at: datetime
    delivered_at: datetime | None


class WebhookView(BaseModel):
    id: uuid.UUID
    name: str
    url: str
    events: list[str]
    enabled: bool
    created_at: datetime
    deliveries: list[DeliveryView]


class CreatedWebhook(BaseModel):
    webhook: WebhookView
    secret: str  # shown once


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="admin", user_id=claims.user_id)


def _delivery_view(d: WebhookDelivery) -> DeliveryView:
    return DeliveryView(
        id=d.id,
        event=d.event,
        status=d.status,
        attempts=d.attempts,
        http_status=d.http_status,
        error=d.error,
        created_at=d.created_at,
        delivered_at=d.delivered_at,
    )


def _view(w: Webhook, deliveries: list[WebhookDelivery]) -> WebhookView:
    return WebhookView(
        id=w.id,
        name=w.name,
        url=w.url,
        events=list(w.events),
        enabled=w.enabled,
        created_at=w.created_at,
        deliveries=[_delivery_view(d) for d in deliveries],
    )


async def list_webhooks(claims: SessionClaims) -> list[WebhookView]:
    async with db_session(_ctx(claims)) as session:
        hooks = (await session.execute(select(Webhook).order_by(Webhook.created_at.desc()))).scalars().all()
        out = []
        for w in hooks:
            recent = (
                (
                    await session.execute(
                        select(WebhookDelivery)
                        .where(WebhookDelivery.webhook_id == w.id)
                        .order_by(WebhookDelivery.created_at.desc())
                        .limit(RECENT_DELIVERIES)
                    )
                )
                .scalars()
                .all()
            )
            out.append(_view(w, list(recent)))
        return out


async def create_webhook(claims: SessionClaims, body: CreateWebhookRequest) -> CreatedWebhook:
    url = body.url.strip()
    try:
        validate_url(url)
    except UnsafeWebhookError as exc:
        raise UnprocessableError(
            "webhook_url_invalid", "Use an https:// address on port 443.", {"reason": str(exc)}
        ) from exc
    name = body.name.strip()
    if not name or any(ord(c) < 32 for c in name):
        raise UnprocessableError("webhook_name_invalid", "Give the webhook a short name.")
    secret = random_token("whsec", 32)
    async with db_session(_ctx(claims)) as session:
        hook = Webhook(
            id=uuid.uuid4(),
            user_id=claims.user_id,
            name=name,
            url=url,
            events=sorted(set(body.events)),
            secret_enc="",
            enabled=True,
        )
        hook.secret_enc = get_settings().keyring.encrypt(secret, _aad(hook.id))
        session.add(hook)
        await session.flush()
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="webhook.created",
            target=str(hook.id),
            metadata={"events": ",".join(hook.events), "host": validate_url(url)[0]},
        )
        return CreatedWebhook(webhook=_view(hook, []), secret=secret)


async def set_enabled(claims: SessionClaims, webhook_id: uuid.UUID, enabled: bool) -> WebhookView:
    async with db_session(_ctx(claims)) as session:
        hook = await session.get(Webhook, webhook_id, with_for_update=True)
        if hook is None:
            raise NotFoundError("webhook_not_found", "This webhook does not exist.")
        hook.enabled, hook.updated_at = enabled, datetime.now(UTC)
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="webhook.enabled" if enabled else "webhook.disabled",
            target=str(hook.id),
        )
        await session.flush()
        return _view(hook, [])


async def ping(claims: SessionClaims, webhook_id: uuid.UUID) -> DeliveryView:
    """Queue a `ping` delivery to this one webhook (even if it is not subscribed to ping)."""
    async with db_session(_ctx(claims)) as session:
        hook = await session.get(Webhook, webhook_id)
        if hook is None:
            raise NotFoundError("webhook_not_found", "This webhook does not exist.")
        if not hook.enabled:
            raise UnprocessableError("webhook_disabled", "Switch the webhook on first.")
        delivery = WebhookDelivery(
            webhook_id=hook.id, event="ping", event_id=f"ping:{uuid.uuid4()}", status="pending"
        )
        session.add(delivery)
        await session.flush()
        await audit.record(
            session, actor=f"admin:{claims.user_id}", action="webhook.pinged", target=str(hook.id)
        )
        view = _delivery_view(delivery)
    await jobs.enqueue_webhook_delivery(view.id)
    return view


# ---- fan-out and delivery (api-jobs) ----


async def fan_out(event: Event, event_id: str) -> list[uuid.UUID]:
    """One delivery per enabled, subscribed webhook (scan events: the scan owner's webhooks only)."""
    async with db_session(DbContext.system()) as session:
        stmt = select(Webhook.id).where(Webhook.enabled.is_(True), Webhook.events.contains([event]))
        if event == "scan.completed":
            owner = (
                await session.execute(select(Scan.user_id).where(Scan.id == uuid.UUID(event_id)))
            ).scalar()
            if owner is None:
                return []
            stmt = stmt.where(Webhook.user_id == owner)
        created: list[uuid.UUID] = []
        for hook_id in (await session.execute(stmt)).scalars().all():
            row = (
                await session.execute(
                    insert(WebhookDelivery)
                    .values(webhook_id=hook_id, event=event, event_id=event_id, status="pending")
                    .on_conflict_do_nothing(index_elements=["webhook_id", "event_id"])
                    .returning(WebhookDelivery.id)
                )
            ).scalar()
            if row is not None:
                created.append(row)
        return created


async def _payload(session: AsyncSession, d: WebhookDelivery) -> dict[str, object] | None:
    base: dict[str, object] = {
        "event": d.event,
        "delivery_id": str(d.id),
        "created_at": d.created_at.isoformat(),
    }
    if d.event == "ping":
        return {**base, "data": {}}
    if d.event == "scan.completed":
        scan = await session.get(Scan, uuid.UUID(d.event_id))
        if scan is None:
            return None
        counts = dict(
            (
                await session.execute(
                    select(Finding.severity, func.count())
                    .where(Finding.scan_id == scan.id)
                    .group_by(Finding.severity)
                )
            ).all()
        )
        return {
            **base,
            "data": {
                "scan_id": str(scan.id),
                "project_id": str(scan.project_id),
                "status": scan.status,
                "score": scan.score,
                "findings": {k: int(v) for k, v in counts.items()},
            },
        }
    alert = await session.get(OpsAlert, uuid.UUID(d.event_id))
    if alert is None:
        return None
    return {
        **base,
        "data": {
            "alert_id": str(alert.id),
            "kind": alert.kind,
            "value": alert.value,
            "threshold": alert.threshold,
            "opened_at": alert.opened_at.isoformat(),
        },
    }


Outcome = Literal["sent", "failed", "retry"]


async def _post(url: str, body: bytes, headers: dict[str, str]) -> int:
    host, path = validate_url(url)
    address = await resolve_public(host)
    literal = f"[{address}]" if ":" in address else address
    async with (
        httpx.AsyncClient(timeout=TIMEOUT_SECONDS, follow_redirects=False, trust_env=False) as client,
        client.stream(
            "POST",
            f"https://{literal}{path}",
            content=body,
            headers={**headers, "Host": host},
            extensions={"sni_hostname": host},  # TLS SNI and certificate check against the name
        ) as response,
    ):
        return response.status_code


async def deliver(delivery_id: uuid.UUID, *, final_try: bool) -> Outcome:
    async with db_session(DbContext.system()) as session:
        d = await session.get(WebhookDelivery, delivery_id)
        if d is None or d.status != "pending":
            return "failed" if d is None else ("sent" if d.status == "sent" else "failed")
        hook = await session.get(Webhook, d.webhook_id)
        payload = await _payload(session, d) if hook is not None and hook.enabled else None
        if hook is None or payload is None:
            d.status, d.error = "failed", "webhook_disabled" if hook is not None else "webhook_gone"
            return "failed"
        url, secret = hook.url, get_settings().keyring.decrypt(hook.secret_enc, _aad(hook.id))
        event = d.event
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    headers = {
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
        "X-GuardHub-Event": event,
        "X-GuardHub-Delivery": str(delivery_id),
        "X-GuardHub-Signature": sign(secret, body, int(time.time())),
    }
    status: int | None = None
    error: str | None = None
    retryable = False
    try:
        status = await _post(url, body, headers)
        retryable = status == 429 or status >= 500
        if not 200 <= status < 300:
            error = f"http_{status}"
    except UnsafeWebhookError as exc:
        error = str(exc)
    except httpx.HTTPError as exc:
        error, retryable = type(exc).__name__[:60], True
    outcome: Outcome = "sent" if error is None else ("retry" if retryable and not final_try else "failed")
    async with db_session(DbContext.system()) as session:
        d = await session.get(WebhookDelivery, delivery_id, with_for_update=True)
        if d is not None:
            d.attempts += 1
            d.http_status, d.error = status, error
            d.payload_sha256 = hashlib.sha256(body).hexdigest()
            if outcome == "sent":
                d.status, d.delivered_at = "sent", datetime.now(UTC)
            elif outcome == "failed":
                d.status = "failed"
    log.info("webhook_delivery", extra={"delivery": str(delivery_id), "outcome": outcome, "error": error})
    return outcome
