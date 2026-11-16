"""Error tracking (Sentry protocol) for api, api-worker and api-jobs.

OFF unless SENTRY_DSN_API (or SENTRY_DSN) is set.

Errors only (traces/profiles sample rate 0) and no PII (§9): `scrub_event` drops request bodies,
cookies, auth/scan-token/CSRF headers, query strings, client IPs, users and local variables. It
does NOT trace requests or attach any request data beyond method + path. When SENTRY_RELAY_URL is
set (production: the `sentry-relay` service), events go to that relay instead of the DSN host,
because api and api-worker have no internet access (api-jobs uses the relay too).

CLI: `python -m guardhub_api.common.observability test-event [--service api|api-worker|api-jobs]`.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Literal, cast
from urllib.parse import urlsplit, urlunsplit

import sentry_sdk
from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict
from sentry_sdk.envelope import Envelope
from sentry_sdk.integrations.logging import LoggingIntegration
from sentry_sdk.transport import Transport

if TYPE_CHECKING:
    from sentry_sdk.types import Breadcrumb, BreadcrumbHint, Event, Hint

Service = Literal["api", "api-worker", "api-jobs"]

FILTERED = "[Filtered]"

# Keys (case-insensitive, `-`/`_` agnostic) whose values never leave the process.
_SENSITIVE_KEYS = frozenset(
    k.replace("-", "_")
    for k in (
        "authorization",
        "proxy-authorization",
        "cookie",
        "cookies",
        "set-cookie",
        "x-scan-token",
        "x-guardhub-csrf",
        "x-forwarded-for",
        "x-real-ip",
        "forwarded",
        "remote_addr",
        "ip_address",
        "client_ip",
        "password",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "totp",
        "code",
        "otp",
        "jwt",
        "session",
        "gh_session",
        "dsn",
        "database_url",
        "redis_url",
        "data_encryption_key",
        "hash_pepper",
        "jwt_secret",
        "ai_api_key",
        "query_string",
        "body",
    )
)
# Request headers that may stay (everything else is dropped).
_SAFE_HEADERS = frozenset({"user-agent", "accept", "accept-language", "content-type", "content-length"})

_URL_USERINFO = re.compile(r"(?P<scheme>\b[a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s@]*@")
_URL_QUERY = re.compile(r"(?P<base>\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s?#\"'<>]*)\?[^\s#\"'<>]*")
_JWT = re.compile(r"\beyJ[\w-]{5,}\.[\w-]{5,}\.[\w-]{5,}")
_GH_TOKEN = re.compile(r"\bgh[a-z]_[A-Za-z0-9_-]{8,}")
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# SQLAlchemy appends bound parameters (emails, hashes...) to DB error messages.
_SQL_PARAMS = re.compile(r"\[parameters: .*", re.DOTALL)


class SentrySettings(BaseSettings):
    """Only the error-tracking settings, so the test-event CLI works without the rest of the env."""

    model_config = SettingsConfigDict(env_file=None, extra="ignore", case_sensitive=False)

    # Per-service DSN (api AND api-worker share the api project); SENTRY_DSN is only a fallback.
    sentry_dsn_api: SecretStr = SecretStr("")
    sentry_dsn: SecretStr = SecretStr("")
    sentry_environment: str = "production"
    # Production: http://sentry-relay:3000 (api/worker have no internet). Empty = DSN host.
    sentry_relay_url: str = ""
    guardhub_version: str = ""

    @property
    def dsn(self) -> str:
        """SENTRY_DSN_API wins; SENTRY_DSN is the fallback; empty means off."""
        return self.sentry_dsn_api.get_secret_value().strip() or self.sentry_dsn.get_secret_value().strip()


def scrub_text(value: str) -> str:
    """Remove credentials, query strings and tokens from free text (messages, exception values)."""
    value = _URL_USERINFO.sub(r"\g<scheme>[Filtered]@", value)
    value = _URL_QUERY.sub(r"\g<base>?[Filtered]", value)
    value = _JWT.sub(FILTERED, value)
    value = _GH_TOKEN.sub(FILTERED, value)
    value = _BEARER.sub(r"\1 [Filtered]", value)
    value = _SQL_PARAMS.sub("[parameters: [Filtered]]", value)
    value = _EMAIL.sub(FILTERED, value)
    return _IPV4.sub(FILTERED, value)


def _is_sensitive(key: str) -> bool:
    return key.lower().replace("-", "_") in _SENSITIVE_KEYS


def scrub_value(value: object) -> object:
    """Recursively scrub a JSON-like value: sensitive keys → [Filtered], strings → scrub_text."""
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, Mapping):
        return {
            str(k): FILTERED if _is_sensitive(str(k)) else scrub_value(v)
            for k, v in cast(Mapping[object, object], value).items()
        }
    if isinstance(value, list | tuple):
        return [scrub_value(v) for v in cast(list[object], value)]
    return value


def _strip_query(url: str) -> str:
    try:
        parts = urlsplit(url)
    except ValueError:
        return FILTERED
    netloc = parts.hostname or ""
    if parts.port:
        netloc = f"{netloc}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _scrub_request(request: dict[str, object]) -> dict[str, object]:
    out: dict[str, object] = {}
    if isinstance(method := request.get("method"), str):
        out["method"] = method
    if isinstance(url := request.get("url"), str):
        out["url"] = _strip_query(url)
    headers = request.get("headers")
    if isinstance(headers, Mapping):
        out["headers"] = {
            str(k): scrub_text(str(v))
            for k, v in cast(Mapping[object, object], headers).items()
            if str(k).lower() in _SAFE_HEADERS
        }
    # data (body), cookies, query_string and env (REMOTE_ADDR) are never kept.
    return out


def _scrub_frames(container: object) -> None:
    if not isinstance(container, dict):
        return
    stacktrace = container.get("stacktrace")
    if isinstance(stacktrace, dict):
        for frame in stacktrace.get("frames") or []:
            if isinstance(frame, dict):
                frame.pop("vars", None)


def scrub_event_dict(event: dict[str, object]) -> dict[str, object]:
    """Privacy filter applied to every event before it leaves the process (pure, unit-tested)."""
    event.pop("user", None)  # no ids, emails or IP addresses
    if isinstance(request := event.get("request"), dict):
        event["request"] = _scrub_request(cast(dict[str, object], request))
    for section in ("exception", "threads"):
        block = event.get(section)
        if isinstance(block, dict):
            for item in block.get("values") or []:
                _scrub_frames(item)
                if isinstance(item, dict) and isinstance(item.get("value"), str):
                    item["value"] = scrub_text(item["value"])
    for key in ("message", "logentry", "extra", "contexts", "tags", "breadcrumbs"):
        if key in event:
            event[key] = scrub_value(event[key])
    return event


def before_send(event: Event, _hint: Hint) -> Event | None:
    return cast("Event", scrub_event_dict(cast(dict[str, object], event)))


def before_breadcrumb(crumb: Breadcrumb, _hint: BreadcrumbHint) -> Breadcrumb | None:
    return cast("Breadcrumb", scrub_value(dict(crumb)))


def effective_dsn(dsn: str, relay_url: str) -> str:
    """Point the DSN at the relay (scheme/host/port replaced, public key + project id kept)."""
    if not dsn or not relay_url:
        return dsn
    parts = urlsplit(dsn)
    relay = urlsplit(relay_url)
    project_id = parts.path.rstrip("/").rsplit("/", 1)[-1]
    if not parts.username or not project_id or not relay.scheme or not relay.netloc:
        raise ValueError("SENTRY_DSN or SENTRY_RELAY_URL is malformed")
    return urlunsplit((relay.scheme, f"{parts.username}@{relay.netloc}", f"/{project_id}", "", ""))


def init_observability(
    service: Service, settings: SentrySettings | None = None, *, transport: Transport | None = None
) -> bool:
    """Start error reporting for `service`. Returns False (and does nothing) without SENTRY_DSN.

    `transport` is only for the test-event CLI; services use the SDK's background HTTP transport.
    """
    settings = settings or SentrySettings()
    dsn = settings.dsn
    if not dsn:
        return False
    sentry_sdk.init(
        dsn=effective_dsn(dsn, settings.sentry_relay_url.strip()),
        environment=settings.sentry_environment or "production",
        release=settings.guardhub_version or None,
        send_default_pii=False,
        include_local_variables=False,
        max_request_body_size="never",
        traces_sample_rate=0.0,
        profiles_sample_rate=0.0,
        before_send=before_send,
        before_breadcrumb=before_breadcrumb,
        in_app_include=["guardhub_api"],
        transport=transport,
        # Logged errors (log.exception / log.error) become events; info logs become breadcrumbs.
        integrations=[LoggingIntegration(level=logging.INFO, event_level=logging.ERROR)],
    )
    sentry_sdk.set_tag("service", service)
    return True


class _HeldTransport(Transport):
    """Keeps envelopes in memory so the test-event CLI can deliver them synchronously."""

    def __init__(self) -> None:
        super().__init__()
        self.envelopes: list[Envelope] = []

    def capture_envelope(self, envelope: Envelope) -> None:
        self.envelopes.append(envelope)


def _post_envelope(dsn: str, body: bytes, timeout: float = 10.0) -> tuple[int, str]:
    """POST one envelope to the DSN's envelope endpoint. Returns (HTTP status or 0, detail)."""
    parts = urlsplit(dsn)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return 0, "DSN must be an http(s) URL"
    prefix, _, project_id = parts.path.rstrip("/").rpartition("/")
    port = f":{parts.port}" if parts.port else ""
    url = f"{parts.scheme}://{parts.hostname}{port}{prefix}/api/{project_id}/envelope/"
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-sentry-envelope",
            "X-Sentry-Auth": f"Sentry sentry_key={parts.username}, sentry_version=7, "
            f"sentry_client=guardhub-test-event/{sentry_sdk.VERSION}",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - http(s) only
            return int(response.status), response.read(300).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(300).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        return 0, str(getattr(exc, "reason", exc))


def send_test_event(service: Service, out: Callable[[str], object] = print) -> int:
    """Send one test event and wait for the answer. Exit: 0 accepted, 1 failed, 2 no DSN.

    The event is built by the real SDK setup (same options, tags and scrubber as the service),
    then POSTed synchronously so a refused connection or a non-2xx answer (wrong key or project,
    relay down, no route) is reported instead of being dropped silently in the background.
    """
    settings = SentrySettings()
    held = _HeldTransport()
    if not init_observability(service, settings, transport=held):
        out("SENTRY_DSN_API (or SENTRY_DSN) is not set; error tracking is off. Nothing was sent.")
        return 2
    client = sentry_sdk.get_client()
    try:
        event_id = sentry_sdk.capture_message(
            f"GuardHub Sentry test event (service={service})", level="error"
        )
        client.flush(timeout=5)
        if event_id is None or not held.envelopes or client.dsn is None:
            out("Delivery FAILED: the SDK did not produce an event.")
            return 1
        status, detail = _post_envelope(str(client.dsn), held.envelopes[0].serialize())
    finally:
        client.close(timeout=2)
    target = f"relay {settings.sentry_relay_url}" if settings.sentry_relay_url else "the DSN host"
    if not 200 <= status < 300:
        reason = f"HTTP {status}: {detail}" if status else f"network error: {detail}"
        out(f"Delivery FAILED via {target} ({reason.strip()}).")
        return 1
    out(f"Sent test event {event_id} (service={service}) via {target}; accepted with HTTP {status}.")
    out("Find it in Sentry by searching for this event id.")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m guardhub_api.common.observability")
    sub = parser.add_subparsers(dest="command", required=True)
    test = sub.add_parser("test-event", help="send one test event and wait for delivery")
    test.add_argument("--service", choices=["api", "api-worker", "api-jobs"], default="api")
    args = parser.parse_args(argv)
    return send_test_event(cast(Service, args.service))


if __name__ == "__main__":
    sys.exit(main())
