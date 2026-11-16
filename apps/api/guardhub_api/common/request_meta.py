"""Request metadata: client IP (proxy-aware) and locale negotiation.

The client IP is taken from X-Forwarded-For only as far as `TRUSTED_PROXY_HOPS` allows, so a
client can't spoof it by sending its own header. Callers store only a keyed hash of the IP.
"""

from __future__ import annotations

from fastapi import Request

from guardhub_api.config import get_settings

SUPPORTED_LOCALES: tuple[str, ...] = ("en", "de", "tr", "fr", "it", "es", "zh-CN", "hi", "ru")
DEFAULT_LOCALE = "en"
_LOWER = {loc.lower(): loc for loc in SUPPORTED_LOCALES}


def client_ip(request: Request) -> str:
    hops = get_settings().trusted_proxy_hops
    peer = request.client.host if request.client else "0.0.0.0"  # noqa: S104 — placeholder, never bound
    if hops == 0:
        return peer
    forwarded = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    chain = [*forwarded, peer]
    # The rightmost `hops` entries were appended by trusted proxies; the client is just before them.
    index = len(chain) - 1 - hops
    return chain[index] if index >= 0 else chain[0]


def match_locale(tag: str | None) -> str | None:
    if not tag:
        return None
    t = tag.strip().replace("_", "-").lower()
    if t in _LOWER:
        return _LOWER[t]
    if t.startswith("zh"):
        return "zh-CN"
    base = t.split("-", 1)[0]
    return _LOWER.get(base)


def negotiate_accept_language(header: str | None) -> str | None:
    if not header:
        return None
    candidates: list[tuple[float, int, str]] = []
    for idx, part in enumerate(header.split(",")):
        piece = part.strip()
        if not piece:
            continue
        tag, _, params = piece.partition(";")
        q = 1.0
        if params.strip().startswith("q="):
            try:
                q = float(params.strip()[2:])
            except ValueError:
                q = 0.0
        if q > 0:
            candidates.append((-q, idx, tag))
    for _, _, tag in sorted(candidates):
        found = match_locale(tag)
        if found:
            return found
    return None


def resolve_locale(explicit: str | None, profile: str | None, accept_language: str | None) -> str:
    return (
        match_locale(explicit)
        or match_locale(profile)
        or negotiate_accept_language(accept_language)
        or DEFAULT_LOCALE
    )
