"""Alerts (§8.4): Slack URL validation (incl. SSRF attempts), Slack/e-mail delivery rules, the
en/tr renderer (brand, escaping, no evidence), and SMTP configuration safety."""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
from cryptography.exceptions import InvalidTag
from pydantic import ValidationError

from guardhub_api.alerts import delivery, render
from guardhub_api.alerts.service import decrypt_webhook, encrypt_webhook
from guardhub_api.common.errors import UnprocessableError
from guardhub_api.config import Settings, get_settings

GOOD = "https://hooks.slack.com/services/T0000AAAA/B0000BBBB/abcdefghijklmnopqrstuvwx"


# ---- Slack webhook URL ----


def test_valid_slack_webhook_accepted() -> None:
    assert delivery.validate_slack_webhook(GOOD) == GOOD
    assert delivery.validate_slack_webhook(f"  {GOOD}  ") == GOOD


@pytest.mark.parametrize(
    "url",
    [
        "",
        "http://hooks.slack.com/services/T0000AAAA/B0000BBBB/abcdefghij",  # not https
        "https://hooks.slack.com.evil.example/services/T0000AAAA/B0000BBBB/abc",  # suffix host
        "https://evil.example/services/T0000AAAA/B0000BBBB/abcdefghij",  # other host
        "https://hooks.slack.com@evil.example/services/T0000AAAA/B0000BBBB/abc",  # userinfo trick
        "https://user:pw@hooks.slack.com/services/T0000AAAA/B0000BBBB/abcdefghij",  # credentials
        "https://hooks.slack.com:8443/services/T0000AAAA/B0000BBBB/abcdefghij",  # port
        "https://hooks.slack.com:443/services/T0000AAAA/B0000BBBB/abcdefghij",  # explicit port
        "https://HOOKS.slack.com/services/T0000AAAA/B0000BBBB/abcdefghij",  # case games
        "https://hooks.slack.com/services/../../redirect?to=http://169.254.169.254/",  # traversal
        "https://hooks.slack.com/services/T0000AAAA/B0000BBBB/abc?next=https://evil.example",  # query
        "https://hooks.slack.com/services/T0000AAAA/B0000BBBB/abcdef#frag",  # fragment
        "https://hooks.slack.com/services/T0000AAAA%2F..%2Fx/abcdefghijk",  # encoded
        "https://hooks.slack.com/services/short",  # too short
        "https://hooks.slack.com/workflows/T0000AAAA/B0000BBBB/abcdefghij",  # other API
        "https://hooks.slack.com/services/T0000AAAA/B0000BBBB/abcdefghij\nhttps://evil.example/x",  # 2 lines
        "https://hooks.slack.com/services/T0000AAAA/B0000BBBB/abc def",  # whitespace inside
        "https://hooks.slack.com/services/T0000AAAA/B0000BBBB/abc\\@evil.example",  # backslash
        "https://hooks.slack.com\\.evil.example/services/T0000AAAA/B0000BBBB/abc",
        "https://hooks。slack.com/services/T0000AAAA/B0000BBBB/abcdefghij",  # unicode dot
        "https://127.0.0.1/services/T0000AAAA/B0000BBBB/abcdefghij",  # IP
        "javascript:alert(1)//hooks.slack.com/services/T0000AAAA/B0000BBBB",
        "https://hooks.slack.com/services/" + "a" * 260,  # too long
    ],
)
def test_invalid_slack_webhooks_rejected(url: str) -> None:
    with pytest.raises(UnprocessableError) as exc:
        delivery.validate_slack_webhook(url)
    assert exc.value.code == "invalid_slack_webhook"


def test_webhook_ciphertext_is_bound_to_the_user() -> None:
    alice, bob = uuid.uuid4(), uuid.uuid4()
    token = encrypt_webhook(alice, GOOD)
    assert token.startswith("v1.") and "slack" not in token
    assert decrypt_webhook(alice, token) == GOOD
    with pytest.raises(InvalidTag):  # AAD = user id: copying the ciphertext to Bob doesn't work
        decrypt_webhook(bob, token)


# ---- Slack delivery ----


def _message() -> render.AlertMessage:
    return render.channel_check_alert("en")


async def test_slack_post_no_redirects_and_status_handling() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="ok")

    await delivery.send_slack(GOOD, _message(), transport=httpx.MockTransport(handler))
    assert len(seen) == 1 and seen[0].url.host == "hooks.slack.com" and seen[0].method == "POST"
    body = json.loads(seen[0].content)
    assert "GuardHub" in body["text"] and body["unfurl_links"] is False

    def redirect(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data"})

    seen.clear()
    with pytest.raises(delivery.DeliveryError) as exc:
        await delivery.send_slack(GOOD, _message(), transport=httpx.MockTransport(redirect))
    assert exc.value.code == "slack_http_302" and not exc.value.retryable
    assert len(seen) == 1  # the redirect was NOT followed

    for status, retryable in ((404, False), (410, False), (429, True), (503, True)):
        with pytest.raises(delivery.DeliveryError) as exc:
            await delivery.send_slack(
                GOOD, _message(), transport=httpx.MockTransport(lambda r, s=status: httpx.Response(s))
            )
        assert exc.value.retryable is retryable


async def test_slack_send_rechecks_url_and_never_contacts_other_hosts() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not send")

    with pytest.raises(delivery.DeliveryError) as exc:
        await delivery.send_slack(
            "https://evil.example/services/T0000AAAA/B0000BBBB/abcdefghij",
            _message(),
            transport=httpx.MockTransport(handler),
        )
    assert exc.value.code == "slack_webhook_invalid"


async def test_slack_timeout_is_retryable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.extensions["timeout"]["read"] == delivery.SLACK_TIMEOUT_SECONDS
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(delivery.DeliveryError) as exc:
        await delivery.send_slack(GOOD, _message(), transport=httpx.MockTransport(handler))
    assert exc.value.code == "slack_timeout" and exc.value.retryable


# ---- renderer ----


def _items() -> list[render.AlertItem]:
    return [
        render.AlertItem("critical", "Secrets file is public <script>", "Anyone can download it & <b>x</b>"),
        render.AlertItem("medium", "No CSP", "Browsers get no script rules. <!channel>"),
    ]


@pytest.mark.parametrize(
    ("locale", "subject_part", "heading", "powered"),
    [
        ("en", "security changes on", "New issues", "Powered by HKSolutions"),
        ("tr", "için güvenlik değişiklikleri", "Yeni sorunlar", "Bir HKSolutions ürünüdür"),
    ],
)
def test_change_alert_en_tr(locale: str, subject_part: str, heading: str, powered: str) -> None:
    msg = render.change_alert(
        locale,
        project="Shop\r\nBcc: victim@example.com",
        target="https://shop.example.com",
        link="http://localhost:3000/account/projects/p/compare/s",
        new=_items(),
        regressed=[],
        fixed_count=2,
        score=63,
        base_score=100,
    )
    assert subject_part in msg.subject and "\n" not in msg.subject and "\r" not in msg.subject
    for body in (msg.text, msg.html, msg.slack):
        assert heading in body and powered in body
        assert "/compare/s" in body
    assert "[" not in msg.subject  # no missing-text markers
    # HTML escaping
    assert "<script>" not in msg.html and "&lt;script&gt;" in msg.html
    assert "<b>x</b>" not in msg.html
    # Slack escaping: no mention / link injection
    assert "<!channel>" not in msg.slack and "&lt;!channel&gt;" in msg.slack
    assert "Guard</span><span" in msg.html  # brand wordmark


def test_tr_texts_are_complete_and_differ_from_en() -> None:
    for key in ("change.subject", "fixed.subject", "paused.subject", "test.subject", "common.footer"):
        assert render.text("tr", key, project="X") != render.text("en", key, project="X")
    assert not render.text("tr", "paused.reason").startswith("[")
    # unknown locale falls back to en per key
    assert render.text("de", "test.subject") == render.text("en", "test.subject")


def test_long_lists_are_truncated() -> None:
    many = [render.AlertItem("low", f"Issue {i}", "s") for i in range(25)]
    msg = render.change_alert(
        "en",
        project="P",
        target="t",
        link="l",
        new=many,
        regressed=[],
        fixed_count=0,
        score=None,
        base_score=None,
    )
    assert "Issue 9" in msg.text and "Issue 10" not in msg.text and "15 more" in msg.text


def test_fixed_and_paused_alerts() -> None:
    fixed = render.fixed_alert(
        "tr", project="P", target="https://p.example", link="L", fixed=_items(), score=100, base_score=60
    )
    assert "düzeltildi" in fixed.subject and "Düzeltilenler" in fixed.text
    paused = render.paused_alert("en", project="P", target="https://p.example", link="L")
    assert "monitoring paused" in paused.subject and "ownership proof" in paused.text


# ---- e-mail ----


def test_email_is_multipart_with_brand(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "smtp_from", "GuardHub <alerts@guardhub.example>")
    mail = delivery.build_email("user@example.com", render.channel_check_alert("tr"))
    assert mail.is_multipart()
    types = [part.get_content_type() for part in mail.iter_parts()]
    assert types == ["text/plain", "text/html"]
    assert mail["To"] == "user@example.com" and mail["Auto-Submitted"] == "auto-generated"
    assert "test bildirimi" in mail["Subject"]


async def test_email_not_configured_and_plaintext_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "smtp_host", "")
    with pytest.raises(delivery.EmailNotConfiguredError):
        await delivery.send_email("u@example.com", _message())
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_security", "none")
    monkeypatch.setattr(settings, "smtp_insecure_hosts", "mailpit")
    with pytest.raises(delivery.DeliveryError) as exc:
        await delivery.send_email("u@example.com", _message())
    assert exc.value.code == "smtp_insecure_refused"


def _settings(**env: str) -> Settings:
    base = {
        "database_url": "postgresql+asyncpg://t:t@127.0.0.1:1/t",
        "redis_url": "redis://127.0.0.1:1/0",
        "jwt_secret": "x" * 40,
        "hash_pepper": "y" * 40,
        "data_encryption_key": get_settings().data_encryption_key.get_secret_value(),
    }
    return Settings(**{**base, **env})  # type: ignore[arg-type]


def test_smtp_settings_validation() -> None:
    assert _settings().smtp_host == ""
    assert _settings(smtp_host="smtp.example.com", smtp_from="a@b.example").smtp_security == "starttls"
    with pytest.raises(ValidationError):  # plaintext to a real host
        _settings(smtp_host="smtp.example.com", smtp_from="a@b.example", smtp_security="none")
    ok = _settings(
        smtp_host="mailpit", smtp_from="a@b.example", smtp_security="none", smtp_insecure_hosts="mailpit"
    )
    assert ok.smtp_insecure_allowlist == frozenset({"mailpit"})
    with pytest.raises(ValidationError):  # credentials never in plaintext
        _settings(
            smtp_host="mailpit",
            smtp_from="a@b.example",
            smtp_security="none",
            smtp_insecure_hosts="mailpit",
            smtp_username="u",
        )
    with pytest.raises(ValidationError):  # header injection in From
        _settings(smtp_host="smtp.example.com", smtp_from="a@b.example\r\nBcc: x@y.example")
    with pytest.raises(ValidationError):
        _settings(smtp_host="smtp.example.com")  # no From
    with pytest.raises(ValidationError):
        _settings(smtp_security="ssl")
