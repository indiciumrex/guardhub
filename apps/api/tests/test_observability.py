"""Error tracking: OFF without a DSN, the relay DSN rewrite, and the privacy scrubber (§9)."""

from __future__ import annotations

import gzip
import http.server
import json
import threading
from collections.abc import Iterator
from typing import ClassVar

import pytest
import sentry_sdk
from pydantic import SecretStr

from guardhub_api.common import observability as obs
from guardhub_api.common.observability import (
    FILTERED,
    SentrySettings,
    effective_dsn,
    init_observability,
    scrub_event_dict,
    scrub_text,
)

DSN = "https://0123456789abcdef0123456789abcdef@o42.ingest.example.io/4501234"


def _event() -> dict[str, object]:
    return {
        "message": "boom for alice@example.com from 203.0.113.9",
        "user": {"id": "u1", "email": "alice@example.com", "ip_address": "203.0.113.9"},
        "request": {
            "method": "POST",
            "url": "https://guardhub.example/api/v1/public/scans/1?locale=en&token=abc",
            "query_string": "locale=en&token=abc",
            "data": {"password": "hunter2-hunter2"},
            "cookies": {"gh_session": "eyJhbGciOi.eyJzdWIiOi.c2lnbmF0dXJl"},
            "env": {"REMOTE_ADDR": "203.0.113.9"},
            "headers": {
                "Authorization": "Bearer abcdefghijklmnop",
                "Cookie": "gh_session=secret",
                "X-Scan-Token": "scan-token-value",
                "X-GuardHub-CSRF": "1",
                "X-Forwarded-For": "203.0.113.9",
                "User-Agent": "Mozilla/5.0",
            },
        },
        "exception": {
            "values": [
                {
                    "type": "ConnectionError",
                    "value": "cannot reach redis://:s3cretpass@redis:6379/0 (token=ghv_abcdefghijkl)",
                    "stacktrace": {
                        "frames": [{"function": "f", "vars": {"password": "hunter2", "token": "x"}}]
                    },
                },
                {
                    "type": "IntegrityError",
                    "value": "duplicate key [SQL: INSERT INTO users] [parameters: ('bob@example.com', 'h')]",
                },
            ]
        },
        "extra": {
            "msg_id": "1-0",
            "access_token": "t0k3n",
            "nested": {"Authorization": "Basic Zm9vOmJhcg=="},
        },
        "tags": {"service": "api"},
        "breadcrumbs": {
            "values": [
                {
                    "category": "httplib",
                    "data": {"url": "https://example.com/x?secret=1", "method": "GET", "status_code": 200},
                }
            ]
        },
    }


def test_scrubber_removes_every_sensitive_field() -> None:
    out = scrub_event_dict(_event())
    dumped = json.dumps(out)
    for leaked in (
        "alice@example.com",
        "bob@example.com",
        "203.0.113.9",
        "hunter2",
        "s3cretpass",
        "ghv_abcdefghijkl",
        "abcdefghijklmnop",
        "scan-token-value",
        "gh_session",
        "token=abc",
        "secret=1",
        "t0k3n",
        "Zm9vOmJhcg==",
        "eyJhbGciOi",
    ):
        assert leaked not in dumped, leaked
    assert "user" not in out
    request = out["request"]
    assert request == {
        "method": "POST",
        "url": "https://guardhub.example/api/v1/public/scans/1",
        "headers": {"User-Agent": "Mozilla/5.0"},
    }
    exc = out["exception"]["values"]  # type: ignore[index]
    assert "vars" not in exc[0]["stacktrace"]["frames"][0]
    assert exc[0]["value"].startswith("cannot reach redis://[Filtered]@redis:6379/0")
    assert out["extra"]["msg_id"] == "1-0"  # type: ignore[index]
    assert out["extra"]["access_token"] == FILTERED  # type: ignore[index]
    assert out["tags"] == {"service": "api"}
    crumb = out["breadcrumbs"]["values"][0]["data"]  # type: ignore[index]
    assert crumb == {"url": "https://example.com/x?[Filtered]", "method": "GET", "status_code": 200}


def test_scrub_text_keeps_harmless_text() -> None:
    assert scrub_text("scan 42 failed: timeout after 2.73.0") == "scan 42 failed: timeout after 2.73.0"


def test_relay_dsn_rewrite_keeps_key_and_project() -> None:
    assert (
        effective_dsn(DSN, "http://sentry-relay:3000")
        == "http://0123456789abcdef0123456789abcdef@sentry-relay:3000/4501234"
    )
    assert effective_dsn(DSN, "") == DSN
    assert effective_dsn("", "http://sentry-relay:3000") == ""
    with pytest.raises(ValueError, match="malformed"):
        effective_dsn("https://o42.ingest.example.io/", "http://sentry-relay:3000")


def test_off_without_dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[object] = []
    monkeypatch.setattr(sentry_sdk, "init", lambda *a, **k: called.append(k))
    assert init_observability("api", SentrySettings(sentry_dsn=SecretStr(""))) is False
    assert called == []
    assert not sentry_sdk.get_client().is_active()


def test_init_options_are_errors_only_and_private(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    tags: dict[str, str] = {}
    monkeypatch.setattr(sentry_sdk, "init", lambda **k: captured.update(k))
    monkeypatch.setattr(sentry_sdk, "set_tag", lambda k, v: tags.update({k: v}))
    settings = SentrySettings(
        sentry_dsn=SecretStr(DSN),
        sentry_environment="staging",
        sentry_relay_url="http://sentry-relay:3000",
        guardhub_version="1.2.3",
    )
    assert init_observability("api-worker", settings) is True
    assert captured["dsn"] == "http://0123456789abcdef0123456789abcdef@sentry-relay:3000/4501234"
    assert captured["environment"] == "staging"
    assert captured["release"] == "1.2.3"
    assert captured["send_default_pii"] is False
    assert captured["include_local_variables"] is False
    assert captured["max_request_body_size"] == "never"
    assert captured["traces_sample_rate"] == 0.0
    assert captured["profiles_sample_rate"] == 0.0
    assert captured["before_send"] is obs.before_send
    assert tags == {"service": "api-worker"}


def test_test_event_cli_fails_without_dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTRY_DSN", "")
    lines: list[str] = []
    assert obs.send_test_event("api", out=lines.append) == 2
    assert "SENTRY_DSN is not set" in lines[0]


class _Sink(http.server.BaseHTTPRequestHandler):
    """Stands in for the relay / Sentry: records envelopes and answers with `status`."""

    status = 200
    bodies: ClassVar[list[bytes]] = []

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        if self.headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        _Sink.bodies.append(body)
        self.send_response(self.status)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *_: object) -> None:
        return


@pytest.fixture
def sink() -> Iterator[tuple[str, type[_Sink]]]:
    _Sink.bodies = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Sink)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", _Sink
    finally:
        server.shutdown()
        _Sink.status = 200


def test_test_event_is_delivered_through_relay_url(
    monkeypatch: pytest.MonkeyPatch, sink: tuple[str, type[_Sink]]
) -> None:
    url, handler = sink
    monkeypatch.setenv("SENTRY_DSN", DSN)
    monkeypatch.setenv("SENTRY_RELAY_URL", url)
    monkeypatch.setenv("GUARDHUB_VERSION", "9.9.9")
    lines: list[str] = []
    assert obs.send_test_event("api-worker", out=lines.append) == 0
    assert "Sent test event" in lines[0]
    sent = b"".join(handler.bodies).decode().replace(" ", "")
    assert '"service":"api-worker"' in sent
    assert '"release":"9.9.9"' in sent


def test_test_event_reports_rejection(monkeypatch: pytest.MonkeyPatch, sink: tuple[str, type[_Sink]]) -> None:
    url, handler = sink
    handler.status = 400
    monkeypatch.setenv("SENTRY_DSN", DSN)
    monkeypatch.setenv("SENTRY_RELAY_URL", url)
    lines: list[str] = []
    assert obs.send_test_event("api", out=lines.append) == 1
    assert "Delivery FAILED" in lines[0]


def test_test_event_reports_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTRY_DSN", DSN)
    monkeypatch.setenv("SENTRY_RELAY_URL", "http://127.0.0.1:1")
    lines: list[str] = []
    assert obs.send_test_event("api", out=lines.append) == 1
