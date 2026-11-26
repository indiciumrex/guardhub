"""Billing (Phase 5C): the provider signature check and which plan an account effectively has."""

from __future__ import annotations

import hashlib
import hmac
import logging
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from guardhub_api.billing.service import effective_plan, handle_webhook, verify_stripe_signature
from guardhub_api.common.errors import NotFoundError
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


async def test_webhook_noise_is_a_quiet_404_never_an_error_report(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Charging off, another provider, or a missing/bad signature: 404, logged below ERROR (the
    Sentry event level), so nothing reaches Sentry and the 5xx alert never counts it."""
    s = get_settings()
    caplog.set_level(logging.DEBUG, logger="guardhub_api.billing.service")
    with pytest.raises(NotFoundError):
        await handle_webhook("stripe", BODY, _sig(NOW), NOW)  # charging off (default)
    monkeypatch.setattr(s, "billing_charging_enabled", True)
    monkeypatch.setattr(s, "billing_provider", "stripe")
    monkeypatch.setattr(s, "billing_webhook_secret", SecretStr(SECRET))
    for provider, signature in (("paddle", _sig(NOW)), ("stripe", ""), ("stripe", _sig(NOW, secret="x"))):
        with pytest.raises(NotFoundError):
            await handle_webhook(provider, BODY, signature, NOW)
    reasons = [getattr(r, "reason", None) for r in caplog.records if r.msg == "billing_webhook_ignored"]
    assert reasons == ["charging_off", "unknown_provider", "signature_invalid", "signature_invalid"]
    assert all(r.levelno < logging.ERROR for r in caplog.records)
