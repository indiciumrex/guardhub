"""Target URL normalisation: turns user input into a canonical origin `scheme://host[:port]`.

Validates *syntax only*. It deliberately refuses IP literals, localhost and internal-looking
names as an early UX guard, but the authoritative anti-SSRF guard is the scanner's dial-time IP
check (docs/architecture.md §3), which also covers DNS rebinding.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from guardhub_api.common.errors import UnprocessableError

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet", ".corp")
_DEFAULT_PORTS = {"http": 80, "https": 443}
_BARE_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?!\d)")


def _invalid(reason: str) -> UnprocessableError:
    return UnprocessableError(
        "invalid_target_url", "The address is not a valid public website.", {"reason": reason}
    )


def _require_public_hostname(host: str) -> None:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise _invalid("ip_literal")
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(label) for label in labels) or labels[-1].isdigit():
        raise _invalid("hostname")
    if host == "localhost" or host.endswith(_BLOCKED_SUFFIXES):
        raise _invalid("internal_hostname")


def normalize_origin(raw: str, *, allow_private_hosts: frozenset[str] = frozenset()) -> str:
    """Return the canonical origin for user input such as `Example.com/path` → `https://example.com`."""
    text = raw.strip()
    if not text or len(text) > 2048 or any(c.isspace() for c in text):
        raise _invalid("malformed")
    if "://" not in text:
        if _BARE_SCHEME.match(text):  # e.g. "javascript:…", "data:…" (but not "example.com:8080")
            raise _invalid("scheme")
        text = "https://" + text
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise _invalid("scheme")
    if parts.username or parts.password:
        raise _invalid("credentials_in_url")
    host = (parts.hostname or "").rstrip(".")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise _invalid("hostname") from exc
    try:
        port = parts.port
    except ValueError as exc:
        raise _invalid("port") from exc

    if host not in allow_private_hosts:
        _require_public_hostname(host)

    origin = f"{scheme}://{host}"
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        origin += f":{port}"
    return origin


def origin_host(origin: str) -> str:
    return urlsplit(origin).hostname or ""
