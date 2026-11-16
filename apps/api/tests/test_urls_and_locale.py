from __future__ import annotations

import pytest
from starlette.requests import Request

from guardhub_api.common.errors import UnprocessableError
from guardhub_api.common.request_meta import (
    client_ip,
    match_locale,
    negotiate_accept_language,
    resolve_locale,
)
from guardhub_api.common.urls import normalize_origin
from guardhub_api.config import get_settings


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com"),
        ("Example.COM/path?q=1#x", "https://example.com"),
        ("http://example.com:80/", "http://example.com"),
        ("https://example.com:443", "https://example.com"),
        ("https://shop.example.co.uk:8443/a", "https://shop.example.co.uk:8443"),
        ("https://bücher.de", "https://xn--bcher-kva.de"),
        ("  example.com  ", "https://example.com"),
    ],
)
def test_normalize_origin_accepts_public_sites(raw: str, expected: str) -> None:
    assert normalize_origin(raw) == expected


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("", "malformed"),
        ("ftp://example.com", "scheme"),
        ("javascript:alert(1)", "scheme"),
        ("https://user:pw@example.com", "credentials_in_url"),
        ("http://127.0.0.1", "ip_literal"),
        ("http://[::1]", "ip_literal"),
        ("http://169.254.169.254", "ip_literal"),
        ("localhost", "hostname"),
        ("http://localhost:8080", "hostname"),
        ("db.internal", "internal_hostname"),
        ("printer.local", "internal_hostname"),
        ("exa mple.com", "malformed"),
        ("https://example.com:99999", "port"),
        ("-bad-.com", "hostname"),
    ],
)
def test_normalize_origin_rejects_non_public(raw: str, reason: str) -> None:
    with pytest.raises(UnprocessableError) as exc:
        normalize_origin(raw)
    assert exc.value.code == "invalid_target_url"
    assert exc.value.details == {"reason": reason}


def test_private_allowlist_only_for_named_hosts() -> None:
    allow = frozenset({"demo-target"})
    assert normalize_origin("http://demo-target:8080", allow_private_hosts=allow) == "http://demo-target:8080"
    with pytest.raises(UnprocessableError):
        normalize_origin("http://other-host", allow_private_hosts=allow)


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("tr-TR,tr;q=0.9,en;q=0.8", "tr"),
        ("de-DE;q=0.4, fr;q=0.9", "fr"),
        ("zh-TW", "zh-CN"),
        ("pt-BR, ja", None),
        ("en;q=0, ru", "ru"),
        ("", None),
    ],
)
def test_accept_language_negotiation(header: str, expected: str | None) -> None:
    assert negotiate_accept_language(header) == expected


def test_locale_resolution_order() -> None:
    assert resolve_locale("tr", "de", "fr") == "tr"
    assert resolve_locale(None, "de", "fr") == "de"
    assert resolve_locale("xx", None, "es-ES") == "es"
    assert resolve_locale(None, None, None) == "en"
    assert match_locale("ZH_cn") == "zh-CN"


def _request(peer: str, xff: str | None) -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff else []
    return Request({"type": "http", "headers": headers, "client": (peer, 1234)})


def test_client_ip_respects_trusted_hops(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = get_settings()
    monkeypatch.setattr(settings, "trusted_proxy_hops", 1)
    # client spoofs "6.6.6.6"; the trusted proxy (peer) appended the real client 1.2.3.4
    assert client_ip(_request("10.0.0.2", "6.6.6.6, 1.2.3.4")) == "1.2.3.4"
    monkeypatch.setattr(settings, "trusted_proxy_hops", 0)
    assert client_ip(_request("10.0.0.2", "6.6.6.6")) == "10.0.0.2"
