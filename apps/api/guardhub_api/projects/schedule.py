"""Scheduled-monitoring time math (docs/architecture.md §8.2). Pure functions, no I/O.

`first_run` adds a jitter that is stable per project (a hash of its id, in [0, 3600) seconds), so
projects scheduled at the same moment don't all hit the scanner at once. `next_run_after` keeps a
project on its own time slot and never returns a time in the past (no catch-up bursts after downtime).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta
from typing import Literal

Frequency = Literal["off", "daily", "weekly"]

INTERVALS: dict[str, timedelta] = {"daily": timedelta(days=1), "weekly": timedelta(days=7)}
JITTER_RANGE_SECONDS = 3600


def jitter(project_id: uuid.UUID) -> timedelta:
    digest = hashlib.sha256(project_id.bytes).digest()
    return timedelta(seconds=int.from_bytes(digest[:8], "big") % JITTER_RANGE_SECONDS)


def interval(frequency: str) -> timedelta:
    try:
        return INTERVALS[frequency]
    except KeyError as exc:
        raise ValueError(f"no interval for frequency {frequency!r}") from exc


def first_run(project_id: uuid.UUID, frequency: str, now: datetime) -> datetime:
    """`now + interval + jitter` (§8.2)."""
    return now + interval(frequency) + jitter(project_id)


def next_run_after(due: datetime, frequency: str, now: datetime) -> datetime:
    """Advance a due time by whole intervals until it is in the future."""
    step = interval(frequency)
    if due > now:
        return due + step
    missed = (now - due) // step
    return due + step * (missed + 1)
