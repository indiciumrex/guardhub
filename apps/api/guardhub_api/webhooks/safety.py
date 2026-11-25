"""Outgoing webhook safety (Admin Panel, Prompt 2 §4): SSRF guards and signing.

GuardHub shares its host with other projects and api-jobs can reach the internet, so a webhook
URL must never become a way into private networks:
- `https://` only, port 443, a host name (no IP literals, no user info), at most 2048 characters;
- at delivery time every address the name resolves to must be globally routable (no private,
  loopback, link-local such as cloud metadata, unique-local, multicast or reserved ranges);
- the request goes to the address that was checked (the name is used only for TLS SNI,
  certificate verification and the Host header), so DNS cannot change between check and use;
- redirects are never followed and the response body is not read beyond a small limit.

Signature: `X-GuardHub-Signature: t=<unix time>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import socket
from urllib.parse import urlsplit

MAX_URL = 2048


class UnsafeWebhookError(ValueError):
    """The URL or the address it resolves to is not allowed."""


def validate_url(url: str) -> tuple[str, str]:
    """(host, path with query) for an allowed URL, else UnsafeWebhookError."""
    if len(url) > MAX_URL or any(ord(c) < 33 for c in url):
        raise UnsafeWebhookError("invalid_url")
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnsafeWebhookError("https_only")
    if parts.username or parts.password or "@" in parts.netloc:
        raise UnsafeWebhookError("no_userinfo")
    if parts.port not in (None, 443):
        raise UnsafeWebhookError("port_443_only")
    host = (parts.hostname or "").rstrip(".").lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise UnsafeWebhookError("no_ip_literal")
    if not host or "." not in host:
        raise UnsafeWebhookError("invalid_host")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
        raise UnsafeWebhookError("private_name")
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return host, path


def is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_multicast or ip.is_reserved or ip.is_loopback or ip.is_link_local)


async def resolve_public(host: str) -> str:
    """One checked address to connect to; every resolved address must be public."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise UnsafeWebhookError("dns_failed") from exc
    addresses = sorted({str(info[4][0]) for info in infos})
    if not addresses:
        raise UnsafeWebhookError("dns_failed")
    if not all(is_public(a) for a in addresses):
        raise UnsafeWebhookError("blocked_address")
    return addresses[0]


def sign(secret: str, body: bytes, timestamp: int) -> str:
    mac = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={mac}"


def verify(secret: str, body: bytes, header: str, now: int, tolerance: int = 300) -> bool:
    """What a receiver does (documented, and used by the tests)."""
    fields = dict(part.split("=", 1) for part in header.split(",") if "=" in part)
    try:
        t = int(fields["t"])
    except (KeyError, ValueError):
        return False
    if abs(now - t) > tolerance:
        return False
    return hmac.compare_digest(sign(secret, body, t), header)
