"""Deterministic security score (docs/architecture.md §5): same findings → same score."""

from __future__ import annotations

from collections.abc import Iterable

SEVERITY_WEIGHTS: dict[str, int] = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")


def compute_score(severities: Iterable[str]) -> int:
    return max(0, 100 - sum(SEVERITY_WEIGHTS[s] for s in severities))


def count_by_severity(severities: Iterable[str]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for s in severities:
        counts[s] += 1
    return counts


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.index(severity)
