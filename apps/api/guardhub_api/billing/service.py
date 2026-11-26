"""Subscriptions and plan limits (Phase 5C). The mechanism is built; charging stays OFF.

- An account's plan: its subscription row (none = free). A running trial counts as its plan
  until trial_ends_at; a daily job ends expired trials (back to free).
- Limits per plan (billing_plans, admin-editable, seeded with today's behaviour): sites, manual
  scans per day, concurrent manual scans, and the module tier (a module whose min_plan ranks
  above the account's plan is left out of its scans).
- A trial: once per account, only for a public plan with trial days, from free.
- Admins assign a plan by hand (e.g. invoiced customers); every change is audited.
- Provider webhooks: verified with the provider's signature (Stripe's scheme first), stored once
  per event id, and applied only while charging is switched on and a provider is configured.
  Checkout (taking money) is not offered until the founder switches charging on.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

import httpx
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.auth.security import SessionClaims
from guardhub_api.common import audit
from guardhub_api.common.errors import (
    ConflictError,
    NotFoundError,
    ServiceUnavailableError,
    UnprocessableError,
)
from guardhub_api.config import get_settings
from guardhub_api.db.models import BillingEvent, BillingPlan, Project, Scan, Subscription, User
from guardhub_api.db.session import DbContext, db_session

log = logging.getLogger(__name__)

PlanKey = Literal["free", "pro", "agency"]
SIGNATURE_TOLERANCE_SECONDS = 300


@dataclass(frozen=True, slots=True)
class Limits:
    plan: str
    rank: int
    max_sites: int
    scans_per_day: int
    concurrent_scans: int


async def _plan_row(session: AsyncSession, key: str) -> BillingPlan:
    row = await session.get(BillingPlan, key)
    if row is None:  # the catalogue is seeded; a missing plan falls back to free
        row = await session.get(BillingPlan, "free")
    assert row is not None
    return row


def effective_plan(sub: Subscription | None, now: datetime) -> str:
    if sub is None:
        return "free"
    if sub.status == "trialing":
        return sub.plan if sub.trial_ends_at and sub.trial_ends_at > now else "free"
    if sub.status in ("active", "past_due"):
        return sub.plan
    return "free"


async def limits_for(user_id: uuid.UUID) -> Limits:
    async with db_session(DbContext.system()) as session:
        sub = (await session.execute(select(Subscription).where(Subscription.user_id == user_id))).scalar()
        plan = await _plan_row(session, effective_plan(sub, datetime.now(UTC)))
        return Limits(plan.key, plan.rank, plan.max_sites, plan.scans_per_day, plan.concurrent_scans)


async def plan_rank_for_checks(session: AsyncSession) -> dict[str, int]:
    rows = await session.execute(select(BillingPlan.key, BillingPlan.rank))
    return {k: int(r) for k, r in rows.all()}


async def check_new_site(user_id: uuid.UUID, current_sites: int) -> None:
    limits = await limits_for(user_id)
    if current_sites >= limits.max_sites:
        raise UnprocessableError(
            "plan_limit_sites", "Your plan's website limit is reached.", {"limit": str(limits.max_sites)}
        )


async def check_manual_scan(session: AsyncSession, user_id: uuid.UUID) -> Limits:
    """Manual scans only (scheduled scans follow the schedule). Raises at a plan limit."""
    limits = await limits_for(user_id)
    since = datetime.now(UTC) - timedelta(days=1)
    today = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Scan)
                .where(Scan.user_id == user_id, Scan.trigger == "manual", Scan.created_at >= since)
            )
        ).scalar_one()
    )
    if today >= limits.scans_per_day:
        raise UnprocessableError(
            "plan_limit_scans_per_day",
            "Your plan's daily scan limit is reached.",
            {"limit": str(limits.scans_per_day)},
        )
    running = int(
        (
            await session.execute(
                select(func.count())
                .select_from(Scan)
                .where(Scan.user_id == user_id, Scan.status.in_(("queued", "running")))
            )
        ).scalar_one()
    )
    if running >= limits.concurrent_scans:
        raise UnprocessableError(
            "plan_limit_concurrency",
            "Wait for a running scan to finish.",
            {"limit": str(limits.concurrent_scans)},
        )
    return limits


# ---- the customer's view ----


class PlanView(BaseModel):
    key: str
    rank: int
    max_sites: int
    scans_per_day: int
    concurrent_scans: int
    trial_days: int
    public: bool


class BillingView(BaseModel):
    plan: str
    status: str
    trial_ends_at: datetime | None
    trial_available: bool
    limits: PlanView
    usage: dict[str, int]
    plans: list[PlanView]
    charging_live: bool
    checkout_plans: list[str]  # paid plans a checkout can start for (empty while charging is off)


def _plan_view(p: BillingPlan) -> PlanView:
    return PlanView(
        key=p.key,
        rank=p.rank,
        max_sites=p.max_sites,
        scans_per_day=p.scans_per_day,
        concurrent_scans=p.concurrent_scans,
        trial_days=p.trial_days,
        public=p.public,
    )


def charging_live() -> bool:
    s = get_settings()
    return bool(
        s.billing_charging_enabled and s.billing_provider and s.billing_webhook_secret.get_secret_value()
    )


async def view(claims: SessionClaims) -> BillingView:
    now = datetime.now(UTC)
    async with db_session(DbContext.system()) as session:
        sub = (
            await session.execute(select(Subscription).where(Subscription.user_id == claims.user_id))
        ).scalar()
        plans = (await session.execute(select(BillingPlan).order_by(BillingPlan.rank))).scalars().all()
        current = await _plan_row(session, effective_plan(sub, now))
        sites = int(
            (
                await session.execute(
                    select(func.count()).select_from(Project).where(Project.user_id == claims.user_id)
                )
            ).scalar_one()
        )
        scans = int(
            (
                await session.execute(
                    select(func.count())
                    .select_from(Scan)
                    .where(
                        Scan.user_id == claims.user_id,
                        Scan.trigger == "manual",
                        Scan.created_at >= now - timedelta(days=1),
                    )
                )
            ).scalar_one()
        )
    trial_available = not (sub and sub.trial_used) and any(
        p.public and p.trial_days > 0 and p.rank > 0 for p in plans
    )
    return BillingView(
        plan=current.key,
        status=sub.status if sub and effective_plan(sub, now) != "free" else "active",
        trial_ends_at=sub.trial_ends_at if sub and sub.status == "trialing" else None,
        trial_available=trial_available,
        limits=_plan_view(current),
        usage={"sites": sites, "scans_today": scans},
        plans=[_plan_view(p) for p in plans if p.public],
        charging_live=charging_live(),
        checkout_plans=[
            p.key for p in plans if p.public and p.rank > current.rank and p.key in checkout_prices()
        ],
    )


# ---- the checkout (final prompt item 7): inert until the founder switches charging on ----

CHECKOUT_HOST = "checkout.stripe.com"


def checkout_prices() -> dict[str, str]:
    """Plan -> provider price id from BILLING_PRICE_IDS, only while charging is live with an API
    key (empty otherwise: no checkout exists). Malformed entries are ignored."""
    s = get_settings()
    if not charging_live() or s.billing_provider != "stripe" or not s.billing_api_key.get_secret_value():
        return {}
    out: dict[str, str] = {}
    for part in s.billing_price_ids.split(","):
        key, _, price = part.strip().partition("=")
        key, price = key.strip(), price.strip()
        if key in ("pro", "agency") and price.startswith("price_") and len(price) <= 255:
            out[key] = price
    return out


class CheckoutStarted(BaseModel):
    url: str


async def _stripe_session(price: str, user: User, plan: str) -> str:
    s = get_settings()
    base = s.public_base_url.rstrip("/")
    form = {
        "mode": "subscription",
        "line_items[0][price]": price,
        "line_items[0][quantity]": "1",
        "success_url": f"{base}/account/plan?checkout=done",
        "cancel_url": f"{base}/account/plan?checkout=cancelled",
        "client_reference_id": str(user.id),
        "customer_email": user.email,
        "subscription_data[metadata][guardhub_user_id]": str(user.id),
        "subscription_data[metadata][guardhub_plan]": plan,
    }
    async with httpx.AsyncClient(timeout=10.0, proxy=s.billing_egress_proxy or None) as client:
        r = await client.post(
            f"{s.billing_api_url.rstrip('/')}/v1/checkout/sessions",
            data=form,
            headers={"Authorization": f"Bearer {s.billing_api_key.get_secret_value()}"},
        )
    url = r.json().get("url") if r.status_code == 200 else None
    if not isinstance(url, str) or not url.startswith(f"https://{CHECKOUT_HOST}/"):
        log.warning("billing_checkout_failed", extra={"status": r.status_code})
        raise ServiceUnavailableError("checkout_unavailable", "The payment page could not be opened.")
    return url


async def start_checkout(claims: SessionClaims, plan: str) -> CheckoutStarted:
    prices = checkout_prices()
    if not prices:
        raise ConflictError("billing_not_live", "Payments are not switched on.")
    now = datetime.now(UTC)
    async with db_session(DbContext.system()) as session:
        row = await session.get(BillingPlan, plan)
        sub = (
            await session.execute(select(Subscription).where(Subscription.user_id == claims.user_id))
        ).scalar()
        current = await _plan_row(session, effective_plan(sub, now))
        user = await session.get(User, claims.user_id)
    if row is None or not row.public or row.rank <= current.rank or plan not in prices or user is None:
        raise UnprocessableError("plan_not_available", "This plan cannot be bought here.")
    url = await _stripe_session(prices[plan], user, plan)
    async with db_session(DbContext.system()) as session:
        await audit.record(
            session,
            actor=f"user:{claims.user_id}",
            action="billing.checkout_started",
            target=str(claims.user_id),
            metadata={"plan": plan},
        )
    return CheckoutStarted(url=url)


async def start_trial(claims: SessionClaims, plan: str) -> BillingView:
    now = datetime.now(UTC)
    async with db_session(DbContext.system()) as session:  # subscriptions change only here (trigger)
        row = await session.get(BillingPlan, plan)
        if row is None or not row.public or row.trial_days <= 0 or row.rank == 0:
            raise UnprocessableError("trial_not_offered", "No trial is offered for this plan.")
        sub = (
            await session.execute(
                select(Subscription).where(Subscription.user_id == claims.user_id).with_for_update()
            )
        ).scalar()
        if sub is not None and (sub.trial_used or effective_plan(sub, now) != "free"):
            raise UnprocessableError("trial_used", "A trial was already used on this account.")
        if sub is None:
            sub = Subscription(user_id=claims.user_id)
            session.add(sub)
        sub.plan, sub.status, sub.trial_used = plan, "trialing", True
        sub.trial_ends_at, sub.updated_at = now + timedelta(days=row.trial_days), now
        await audit.record(
            session,
            actor=f"user:{claims.user_id}",
            action="billing.trial_started",
            target=str(claims.user_id),
            metadata={"plan": plan, "days": str(row.trial_days)},
        )
    return await view(claims)


async def end_expired_trials(now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    async with db_session(DbContext.system()) as session:
        rows = (
            (
                await session.execute(
                    select(Subscription).where(
                        Subscription.status == "trialing", Subscription.trial_ends_at <= now
                    )
                )
            )
            .scalars()
            .all()
        )
        for sub in rows:
            previous = sub.plan
            sub.plan, sub.status, sub.updated_at = "free", "active", now
            await audit.record(
                session,
                actor="system:billing",
                action="billing.trial_ended",
                target=str(sub.user_id),
                metadata={"plan": previous},
            )
        return len(rows)


# ---- the admin's screen ----


class UpdatePlan(BaseModel):
    max_sites: int = Field(ge=1, le=1000)
    scans_per_day: int = Field(ge=1, le=10000)
    concurrent_scans: int = Field(ge=1, le=100)
    trial_days: int = Field(ge=0, le=90)
    public: bool


class AssignPlan(BaseModel):
    email: EmailStr
    plan: PlanKey
    reason: str = Field(min_length=3, max_length=200)


class AdminSubscription(BaseModel):
    user_id: uuid.UUID
    email: str
    plan: str
    effective_plan: str
    status: str
    trial_ends_at: datetime | None
    provider: str | None
    updated_at: datetime


class AdminBillingView(BaseModel):
    plans: list[PlanView]
    subscriptions: list[AdminSubscription]
    charging_enabled: bool
    provider: str
    webhook_secret_configured: bool
    api_key_configured: bool
    charging_live: bool


def _ctx(claims: SessionClaims) -> DbContext:
    return DbContext(role="admin", user_id=claims.user_id)


async def admin_view(claims: SessionClaims) -> AdminBillingView:
    now = datetime.now(UTC)
    s = get_settings()
    async with db_session(_ctx(claims)) as session:
        plans = (await session.execute(select(BillingPlan).order_by(BillingPlan.rank))).scalars().all()
        subs = (
            await session.execute(
                select(Subscription, User.email)
                .join(User, User.id == Subscription.user_id)
                .order_by(Subscription.updated_at.desc())
                .limit(500)
            )
        ).all()
    return AdminBillingView(
        plans=[_plan_view(p) for p in plans],
        subscriptions=[
            AdminSubscription(
                user_id=sub.user_id,
                email=email,
                plan=sub.plan,
                effective_plan=effective_plan(sub, now),
                status=sub.status,
                trial_ends_at=sub.trial_ends_at,
                provider=sub.provider,
                updated_at=sub.updated_at,
            )
            for sub, email in subs
        ],
        charging_enabled=s.billing_charging_enabled,
        provider=s.billing_provider,
        webhook_secret_configured=bool(s.billing_webhook_secret.get_secret_value()),
        api_key_configured=bool(s.billing_api_key.get_secret_value()),
        charging_live=charging_live(),
    )


async def update_plan(claims: SessionClaims, key: str, body: UpdatePlan) -> PlanView:
    async with db_session(_ctx(claims)) as session:
        row = await session.get(BillingPlan, key, with_for_update=True)
        if row is None:
            raise NotFoundError("plan_not_found", "This plan does not exist.")
        if key == "free" and not body.public:
            raise UnprocessableError("free_plan_public", "The free plan stays public.")
        before = _plan_view(row).model_dump()
        row.max_sites, row.scans_per_day, row.concurrent_scans = (
            body.max_sites,
            body.scans_per_day,
            body.concurrent_scans,
        )
        row.trial_days, row.public = (0 if key == "free" else body.trial_days), body.public
        row.updated_by, row.updated_at = claims.user_id, datetime.now(UTC)
        after = _plan_view(row).model_dump()
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="billing.plan_changed",
            target=key,
            metadata={k: f"{before[k]} -> {after[k]}" for k in after if before[k] != after[k]},
        )
        return _plan_view(row)


async def assign_plan(claims: SessionClaims, body: AssignPlan) -> AdminSubscription:
    now = datetime.now(UTC)
    async with db_session(_ctx(claims)) as session:
        user = (await session.execute(select(User).where(User.email == str(body.email).lower()))).scalar()
        if user is None:
            raise NotFoundError("user_not_found", "User not found.")
        user_id = user.id
        sub = (
            await session.execute(
                select(Subscription).where(Subscription.user_id == user_id).with_for_update()
            )
        ).scalar()
        if sub is None:
            sub = Subscription(user_id=user_id)
            session.add(sub)
        previous = sub.plan if sub.plan else "free"
        sub.plan, sub.status, sub.trial_ends_at, sub.updated_at = body.plan, "active", None, now
        sub.provider = sub.provider or "manual"
        await audit.record(
            session,
            actor=f"admin:{claims.user_id}",
            action="billing.plan_assigned",
            target=str(user_id),
            metadata={"from": previous, "to": body.plan, "reason": body.reason},
        )
        await session.flush()
        return AdminSubscription(
            user_id=user_id,
            email=user.email,
            plan=sub.plan,
            effective_plan=effective_plan(sub, now),
            status=sub.status,
            trial_ends_at=None,
            provider=sub.provider,
            updated_at=now,
        )


# ---- provider webhooks (charging switched off until the founder's go) ----


def verify_stripe_signature(secret: str, body: bytes, header: str, now: int) -> bool:
    """Stripe's scheme: `t=<ts>,v1=<hex HMAC-SHA256(secret, "<ts>.<body>")>`, 5-minute window."""
    parts = [p.split("=", 1) for p in header.split(",") if "=" in p]
    ts = next((v for k, v in parts if k == "t"), "")
    sigs = [v for k, v in parts if k == "v1"]
    if not ts.isdigit() or not sigs or abs(now - int(ts)) > SIGNATURE_TOLERANCE_SECONDS:
        return False
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, s) for s in sigs)


async def handle_webhook(provider: str, body: bytes, signature: str, now: int) -> str:
    s = get_settings()
    if not charging_live() or provider != s.billing_provider:
        raise ServiceUnavailableError("billing_not_live", "Payments are not switched on.")
    if provider != "stripe" or not verify_stripe_signature(
        s.billing_webhook_secret.get_secret_value(), body, signature, now
    ):
        raise UnprocessableError("billing_signature_invalid", "The webhook signature is not valid.")
    try:
        event = json.loads(body)
        event_id, kind = str(event["id"]), str(event["type"])
    except (ValueError, KeyError, TypeError) as exc:
        raise UnprocessableError("billing_event_invalid", "Not a provider event.") from exc
    async with db_session(DbContext.system()) as session:
        stored = (
            await session.execute(
                insert(BillingEvent)
                .values(
                    provider=provider,
                    event_id=event_id[:255],
                    type=kind[:100],
                    payload_sha256=hashlib.sha256(body).hexdigest(),
                )
                .on_conflict_do_nothing(index_elements=["provider", "event_id"])
                .returning(BillingEvent.event_id)
            )
        ).scalar()
        if stored is None:
            return "duplicate"
        if kind.startswith("customer.subscription."):
            await _apply_subscription(session, provider, event.get("data", {}).get("object", {}), kind)
    return "ok"


async def _apply_subscription(
    session: AsyncSession, provider: str, obj: dict[str, object], kind: str
) -> None:
    """The checkout this mechanism creates tags the provider subscription with
    metadata.guardhub_user_id and metadata.guardhub_plan; anything else is ignored."""
    meta = obj.get("metadata") if isinstance(obj.get("metadata"), dict) else {}
    assert isinstance(meta, dict)
    try:
        user_id = uuid.UUID(str(meta.get("guardhub_user_id")))
    except ValueError:
        return
    plan = str(meta.get("guardhub_plan", ""))
    if plan not in ("pro", "agency"):
        return
    status = str(obj.get("status", ""))
    sub = (
        await session.execute(select(Subscription).where(Subscription.user_id == user_id).with_for_update())
    ).scalar()
    if sub is None:
        sub = Subscription(user_id=user_id)
        session.add(sub)
    deleted = kind.endswith(".deleted") or status in ("canceled", "incomplete_expired", "unpaid")
    sub.plan = "free" if deleted else plan
    sub.status = "canceled" if deleted else ("past_due" if status == "past_due" else "active")
    sub.provider, sub.updated_at = provider, datetime.now(UTC)
    sub.provider_customer_id = str(obj.get("customer", ""))[:255] or sub.provider_customer_id
    sub.provider_subscription_id = str(obj.get("id", ""))[:255] or sub.provider_subscription_id
    await audit.record(
        session,
        actor=f"system:billing:{provider}",
        action="billing.subscription_synced",
        target=str(user_id),
        metadata={"plan": sub.plan, "status": sub.status, "event": kind},
    )
