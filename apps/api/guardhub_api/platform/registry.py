"""The fixed list of runtime tunables an admin may change (Admin Panel, Prompt 2 §1).

Each entry has a type, hard bounds and a default (the environment value, or today's constant), so
an empty platform_settings table behaves exactly like before. The admin can only pick a value
inside the bounds; nothing else is reachable from the configuration screen.

Deliberately NOT here, and never to be added (tests/test_platform_registry.py enforces it):
- the four active-testing locks (founder approval, scanner switch, module switches, kill switch);
- ownership proof (§9.2) and its timeouts, sign-in and 2FA limits, sessions and secrets.
They stay in code and in the environment file, and the screen shows them read-only.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from guardhub_api.config import get_settings

Kind = Literal["int", "bool", "text"]
Group = Literal["maintenance", "flags", "scans", "concurrency", "rate_limits"]

SCAN_DEADLINE_MAX = 300  # the scanner's ceiling; the stuck-scan reaper waits at least this long

# Words that may never appear in a tunable's key: these areas are security code, not configuration.
FORBIDDEN_KEY_PARTS = ("active", "kill", "approv", "owner", "verif", "proof", "trusted", "login",
                       "totp", "mfa", "session", "secret", "key", "token", "password", "egress")  # fmt: skip


@dataclass(frozen=True, slots=True)
class Tunable:
    key: str
    group: Group
    kind: Kind
    default: Callable[[], int | bool | str]
    minimum: int | None = None
    maximum: int | None = None
    max_length: int | None = None


def _const(value: int | bool | str) -> Callable[[], int | bool | str]:
    return lambda: value


TUNABLES: tuple[Tunable, ...] = (
    Tunable("maintenance.enabled", "maintenance", "bool", _const(False)),
    Tunable("maintenance.message", "maintenance", "text", _const(""), max_length=280),
    Tunable("flags.public_scan", "flags", "bool", _const(True)),
    Tunable("flags.registration", "flags", "bool", _const(True)),
    Tunable("flags.scheduled_scans", "flags", "bool", _const(True)),
    Tunable(
        "scan.deadline_seconds",
        "scans",
        "int",
        lambda: get_settings().scan_deadline_seconds,
        minimum=30,
        maximum=SCAN_DEADLINE_MAX,
    ),
    Tunable(
        "scheduler.batch",
        "concurrency",
        "int",
        lambda: get_settings().scheduler_batch,
        minimum=1,
        maximum=100,
    ),
    Tunable(
        "scheduler.max_inflight",
        "concurrency",
        "int",
        lambda: get_settings().scheduler_max_inflight,
        minimum=1,
        maximum=50,
    ),
    Tunable("rate.challenge_per_ip_hour", "rate_limits", "int", _const(10), minimum=1, maximum=50),
    Tunable("rate.anon_scan_per_ip_hour", "rate_limits", "int", _const(5), minimum=1, maximum=20),
    Tunable("rate.anon_scan_per_target_hour", "rate_limits", "int", _const(5), minimum=1, maximum=20),
    Tunable("rate.rescan_per_project_hour", "rate_limits", "int", _const(10), minimum=1, maximum=30),
    Tunable("rate.register_per_ip_hour", "rate_limits", "int", _const(5), minimum=1, maximum=20),
)

BY_KEY: dict[str, Tunable] = {t.key: t for t in TUNABLES}


class InvalidValueError(ValueError):
    """The value does not fit the tunable's type or bounds."""


def coerce(t: Tunable, raw: object) -> int | bool | str:
    """The value as stored, or InvalidValueError. Strict: no "1" for True, no 1.5 for an int."""
    if t.kind == "bool":
        if not isinstance(raw, bool):
            raise InvalidValueError("expected true or false")
        return raw
    if t.kind == "int":
        if isinstance(raw, bool) or not isinstance(raw, int):
            raise InvalidValueError("expected a whole number")
        if (t.minimum is not None and raw < t.minimum) or (t.maximum is not None and raw > t.maximum):
            raise InvalidValueError(f"expected {t.minimum} to {t.maximum}")
        return raw
    if not isinstance(raw, str):
        raise InvalidValueError("expected text")
    text = raw.strip()
    if t.max_length is not None and len(text) > t.max_length:
        raise InvalidValueError(f"at most {t.max_length} characters")
    if any(ord(c) < 32 for c in text):
        raise InvalidValueError("no control characters")
    return text
