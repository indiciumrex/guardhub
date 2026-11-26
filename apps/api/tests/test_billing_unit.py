"""Billing (Phase 5C): the provider signature check and which plan an account effectively has."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from guardhub_api.billing.service import checkout_prices, effective_plan, verify_stripe_signature
from guardhub_api.config import get_settings
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


def test_checkout_prices_exist_only_while_charging_is_live(monkeypatch: pytest.MonkeyPatch) -> None:
    s = get_settings()
    monkeypatch.setattr(s, "billing_price_ids", "pro=price_123,agency=price_456")
    assert checkout_prices() == {}  # charging off (default): no checkout at all
    monkeypatch.setattr(s, "billing_charging_enabled", True)
    monkeypatch.setattr(s, "billing_provider", "stripe")
    monkeypatch.setattr(s, "billing_webhook_secret", SecretStr(SECRET))
    assert checkout_prices() == {}  # no API key yet
    monkeypatch.setattr(s, "billing_api_key", SecretStr("sk_test_x"))
    assert checkout_prices() == {"pro": "price_123", "agency": "price_456"}
    monkeypatch.setattr(s, "billing_price_ids", " pro = price_1 , free=price_2, agency=nope, x")
    assert checkout_prices() == {"pro": "price_1"}  # unknown plans and malformed ids are ignored
