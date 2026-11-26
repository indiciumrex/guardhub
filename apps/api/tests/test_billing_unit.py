"""Billing (Phase 5C): the provider signature check and which plan an account effectively has."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import UTC, datetime, timedelta

from guardhub_api.billing.service import effective_plan, verify_stripe_signature
from guardhub_api.db.models import Subscription

SECRET = "whsec_test"
BODY = b'{"id":"evt_1","type":"customer.subscription.updated"}'
NOW = 1_800_000_000


def _sig(ts: int, body: bytes = BODY, secret: str = SECRET) -> str:
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def test_stripe_signature() -> None:
    assert verify_stripe_signature(SECRET, BODY, _sig(NOW), NOW + 10)
    assert verify_stripe_signature(SECRET, BODY, f"{_sig(NOW)},v1=deadbeef", NOW)  # any listed v1 may match
    assert not verify_stripe_signature(SECRET, BODY + b" ", _sig(NOW), NOW)
    assert not verify_stripe_signature("whsec_other", BODY, _sig(NOW), NOW)
    assert not verify_stripe_signature(SECRET, BODY, _sig(NOW - 301), NOW)  # replay window
    assert not verify_stripe_signature(SECRET, BODY, "v1=abc", NOW)
    assert not verify_stripe_signature(SECRET, BODY, "", NOW)


def _sub(**kw: object) -> Subscription:
    return Subscription(user_id=uuid.uuid4(), **kw)


def test_effective_plan() -> None:
    now = datetime(2026, 11, 26, tzinfo=UTC)
    assert effective_plan(None, now) == "free"
    assert effective_plan(_sub(plan="pro", status="active"), now) == "pro"
    assert effective_plan(_sub(plan="pro", status="past_due"), now) == "pro"
    assert effective_plan(_sub(plan="pro", status="canceled"), now) == "free"
    assert (
        effective_plan(_sub(plan="pro", status="trialing", trial_ends_at=now + timedelta(days=1)), now)
        == "pro"
    )
    assert (
        effective_plan(_sub(plan="pro", status="trialing", trial_ends_at=now - timedelta(seconds=1)), now)
        == "free"
    )
