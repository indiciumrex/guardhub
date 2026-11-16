"""Alert delivery channels (docs/architecture.md §8.4). Runs only in `api-jobs` (the one Python
process with egress).

- E-mail: SMTP with STARTTLS (required, not opportunistic) or implicit TLS, certificates validated,
  TLS ≥ 1.2. Plaintext only for a host listed in SMTP_INSECURE_HOSTS (a local sink), and never
  with credentials. No SMTP_HOST → `EmailNotConfiguredError` (the alert is recorded as skipped).
- Slack: incoming webhooks only. The URL must match `SLACK_WEBHOOK_RE` exactly (checked when it
  is saved AND again right before sending); POST with a 5 s timeout, no redirects, no proxies
  from the environment, and nothing but hooks.slack.com:443.
Errors carry a short code only (never server replies, addresses or URLs) and say if a retry helps.
"""

from __future__ import annotations

import re
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

import aiosmtplib
import httpx

from guardhub_api.alerts.render import AlertMessage
from guardhub_api.common.errors import UnprocessableError
from guardhub_api.config import get_settings

SLACK_WEBHOOK_RE = re.compile(r"^https://hooks\.slack\.com/services/[A-Za-z0-9_/-]{10,200}\Z")
SLACK_HOST = "hooks.slack.com"
SLACK_TIMEOUT_SECONDS = 5.0


class DeliveryError(Exception):
    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


class EmailNotConfiguredError(Exception):
    """SMTP_HOST is empty: e-mail alerts are skipped, not failed."""


# ---- Slack ----


def validate_slack_webhook(raw: str) -> str:
    """Return the webhook URL or raise 422 `invalid_slack_webhook`. Exact match only: no other
    host, scheme, port, userinfo, query, fragment, dot segments or encoded characters."""
    candidate = raw.strip()
    if len(candidate) > 250 or not SLACK_WEBHOOK_RE.fullmatch(candidate):
        raise UnprocessableError(
            "invalid_slack_webhook", "Use a Slack incoming webhook URL (https://hooks.slack.com/services/…)."
        )
    url = httpx.URL(candidate)  # defence in depth: the parsed URL must agree with the regex
    if url.scheme != "https" or url.host != SLACK_HOST or url.port is not None or url.userinfo or url.query:
        raise UnprocessableError("invalid_slack_webhook", "Use a Slack incoming webhook URL.")
    return candidate


async def send_slack(
    webhook_url: str, message: AlertMessage, *, transport: httpx.AsyncBaseTransport | None = None
) -> None:
    try:
        url = validate_slack_webhook(webhook_url)
    except UnprocessableError as exc:
        raise DeliveryError("slack_webhook_invalid", retryable=False) from exc
    try:
        async with httpx.AsyncClient(
            timeout=SLACK_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False, transport=transport
        ) as client:
            response = await client.post(url, json={"text": message.slack, "unfurl_links": False})
    except httpx.TimeoutException as exc:
        raise DeliveryError("slack_timeout", retryable=True) from exc
    except httpx.HTTPError as exc:
        raise DeliveryError("slack_unreachable", retryable=True) from exc
    if response.status_code == 200:
        return
    # 4xx (bad/revoked webhook, archived channel) won't fix itself; 429/5xx may.
    retryable = response.status_code == 429 or response.status_code >= 500
    raise DeliveryError(f"slack_http_{response.status_code}", retryable=retryable)


# ---- e-mail ----


def build_email(to: str, message: AlertMessage) -> EmailMessage:
    settings = get_settings()
    mail = EmailMessage()
    mail["From"] = settings.smtp_from
    mail["To"] = to
    mail["Subject"] = message.subject  # already one line (render.one_line)
    mail["Date"] = formatdate(localtime=False)
    mail["Message-ID"] = make_msgid(domain="guardhub")
    mail["Auto-Submitted"] = "auto-generated"
    mail.set_content(message.text)
    mail.add_alternative(message.html, subtype="html")
    return mail


def _tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


async def send_email(to: str, message: AlertMessage) -> None:
    settings = get_settings()
    host = settings.smtp_host.strip()
    if not host:
        raise EmailNotConfiguredError
    security = settings.smtp_security
    plaintext = security == "none"
    if plaintext and (host.lower() not in settings.smtp_insecure_allowlist or settings.smtp_username):
        # Settings validation already refuses this; checked again right before anything leaves.
        raise DeliveryError("smtp_insecure_refused", retryable=False)
    try:
        await aiosmtplib.send(
            build_email(to, message),
            hostname=host,
            port=settings.smtp_port,
            username=settings.smtp_username or None,
            password=settings.smtp_password.get_secret_value() or None,
            use_tls=security == "tls",
            start_tls=security == "starttls",  # True = required (False only for the allow-listed sink)
            validate_certs=not plaintext,
            tls_context=None if plaintext else _tls_context(),
            timeout=settings.smtp_timeout_seconds,
        )
    except aiosmtplib.SMTPRecipientsRefused as exc:
        raise DeliveryError("smtp_recipient_refused", retryable=False) from exc
    except aiosmtplib.SMTPAuthenticationError as exc:
        raise DeliveryError("smtp_auth_failed", retryable=False) from exc
    except (aiosmtplib.SMTPException, OSError, TimeoutError) as exc:
        raise DeliveryError("smtp_error", retryable=True) from exc
