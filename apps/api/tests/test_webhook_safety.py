"""Outgoing webhooks (Prompt 2 §4): SSRF guards and signatures, without any network."""

from __future__ import annotations

import asyncio
import socket

import pytest

from guardhub_api.webhooks import safety
from guardhub_api.webhooks.safety import UnsafeWebhookError, is_public, sign, validate_url, verify


def test_allowed_url() -> None:
    assert validate_url("https://hooks.example.com/in/abc?x=1") == ("hooks.example.com", "/in/abc?x=1")
    assert validate_url("https://Hooks.Example.com:443") == ("hooks.example.com", "/")


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://hooks.example.com/x", "https_only"),
        ("https://hooks.example.com:8443/x", "port_443_only"),
        ("https://10.0.0.5/x", "no_ip_literal"),
        ("https://[::1]/x", "no_ip_literal"),
        ("https://user:pw@hooks.example.com/x", "no_userinfo"),
        ("https://localhost/x", "invalid_host"),
        ("https://api.localhost/x", "private_name"),
        ("https://metadata.google.internal/x", "private_name"),
        ("https://intranet/x", "invalid_host"),
        ("https://hooks.example.com/a b", "invalid_url"),
        ("https://" + "a" * 2050 + ".com", "invalid_url"),
    ],
)
def test_refused_urls(url: str, reason: str) -> None:
    with pytest.raises(UnsafeWebhookError, match=reason):
        validate_url(url)


@pytest.mark.parametrize(
    ("address", "public"),
    [
        ("8.8.8.8", True),
        ("2606:4700:4700::1111", True),
        ("10.1.2.3", False),
        ("172.17.0.1", False),  # docker bridge
        ("192.168.1.1", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),  # cloud metadata
        ("100.64.0.1", False),  # carrier-grade NAT
        ("0.0.0.0", False),
        ("224.0.0.1", False),
        ("::1", False),
        ("fc00::1", False),
        ("fe80::1", False),
        ("::ffff:10.0.0.1", False),  # IPv4-mapped private
        ("::ffff:8.8.8.8", True),
    ],
)
def test_public_addresses_only(address: str, public: bool) -> None:
    assert is_public(address) is public


def _fake_getaddrinfo(addresses: list[str]):
    async def fake(host: str, port: int, type: int = 0) -> list[tuple[object, ...]]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in addresses]

    return fake


async def test_one_private_answer_blocks_the_whole_name(monkeypatch: pytest.MonkeyPatch) -> None:
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "getaddrinfo", _fake_getaddrinfo(["93.184.216.34", "10.0.0.7"]))
    with pytest.raises(UnsafeWebhookError, match="blocked_address"):
        await safety.resolve_public("rebind.example.com")
    monkeypatch.setattr(loop, "getaddrinfo", _fake_getaddrinfo(["93.184.216.35", "93.184.216.34"]))
    assert await safety.resolve_public("hooks.example.com") == "93.184.216.34"


def test_signature_round_trip_and_tampering() -> None:
    body = b'{"event":"ping"}'
    header = sign("whsec_test", body, 1_800_000_000)
    assert header.startswith("t=1800000000,v1=")
    assert verify("whsec_test", body, header, now=1_800_000_100)
    assert not verify("whsec_test", body + b" ", header, now=1_800_000_100)
    assert not verify("whsec_other", body, header, now=1_800_000_100)
    assert not verify("whsec_test", body, header, now=1_800_000_000 + 301)  # replay window
    assert not verify("whsec_test", body, "v1=abc", now=1_800_000_000)
