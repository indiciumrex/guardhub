"""Scan diff engine (docs/architecture.md §8.3, GUARDHUB_STANDARDS §8.6). Pure: no I/O, no clock.

Compares a done scan S with an earlier done scan B of the same project, by finding fingerprint:
- new:       in S, not in B, and not seen in any done scan before B;
- regressed: in S, not in B, but seen in some done scan before B (it came back);
- fixed:     in B, not in S.
Only checks that ran successfully in BOTH scans are compared, so a check that failed (timeout,
unreachable target) never makes its findings look "fixed" or "new". Without B the result is a
baseline: every list is empty. The caller loads the data and renders texts; this module only decides.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass, field

from guardhub_api.findings.scoring import severity_rank


@dataclass(frozen=True, slots=True)
class DiffFinding:
    fingerprint: str
    check_id: str
    finding_key: str
    severity: str
    params: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanSnapshot:
    """What the diff needs from one scan: which checks ran, which failed, and its findings."""

    scan_id: uuid.UUID
    checks: tuple[str, ...]
    failed_checks: frozenset[str]
    findings: tuple[DiffFinding, ...]

    @property
    def succeeded_checks(self) -> tuple[str, ...]:
        return tuple(c for c in self.checks if c not in self.failed_checks)


@dataclass(frozen=True, slots=True)
class DiffResult:
    base_scan_id: uuid.UUID | None
    compared_checks: tuple[str, ...]
    skipped_checks: tuple[str, ...]
    new: tuple[DiffFinding, ...]
    regressed: tuple[DiffFinding, ...]
    fixed: tuple[DiffFinding, ...]
    unchanged_count: int

    @property
    def is_baseline(self) -> bool:
        return self.base_scan_id is None

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.regressed or self.fixed)


def _ordered_union(*groups: Iterable[str]) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for group in groups:
        for item in group:
            seen.setdefault(item, None)
    return tuple(seen)


def compared_checks(current: ScanSnapshot, base: ScanSnapshot | None) -> tuple[str, ...]:
    """Checks that ran successfully in both scans (in the current scan's catalog order)."""
    if base is None:
        return current.succeeded_checks
    ok_in_base = set(base.succeeded_checks)
    return tuple(c for c in current.succeeded_checks if c in ok_in_base)


def _by_fingerprint(snapshot: ScanSnapshot, checks: AbstractSet[str]) -> dict[str, DiffFinding]:
    return {f.fingerprint: f for f in snapshot.findings if f.check_id in checks}


def appeared_fingerprints(current: ScanSnapshot, base: ScanSnapshot) -> set[str]:
    """Fingerprints in S but not in B (over the compared checks): the ones whose history matters.

    The caller asks the database which of these were seen in a done scan before B.
    """
    checks = set(compared_checks(current, base))
    return set(_by_fingerprint(current, checks)) - set(_by_fingerprint(base, checks))


def compute_diff(
    current: ScanSnapshot, base: ScanSnapshot | None, seen_before_base: AbstractSet[str] = frozenset()
) -> DiffResult:
    """Diff S (`current`) against B (`base`). `seen_before_base` = fingerprints found in any done
    scan of the project created before B (only the ones in `appeared_fingerprints` matter)."""
    compared = compared_checks(current, base)
    if base is None:
        return DiffResult(
            base_scan_id=None,
            compared_checks=compared,
            skipped_checks=tuple(c for c in current.checks if c in current.failed_checks),
            new=(),
            regressed=(),
            fixed=(),
            unchanged_count=len(current.findings),
        )
    compared_set = set(compared)
    now = _by_fingerprint(current, compared_set)
    before = _by_fingerprint(base, compared_set)
    appeared = [f for fp, f in now.items() if fp not in before]
    return DiffResult(
        base_scan_id=base.scan_id,
        compared_checks=compared,
        skipped_checks=tuple(c for c in _ordered_union(current.checks, base.checks) if c not in compared_set),
        new=tuple(f for f in appeared if f.fingerprint not in seen_before_base),
        regressed=tuple(f for f in appeared if f.fingerprint in seen_before_base),
        fixed=tuple(f for fp, f in before.items() if fp not in now),
        unchanged_count=sum(1 for fp in now if fp in before),
    )


def sort_by_severity_then_title[T](
    items: Sequence[T], severity: Callable[[T], str], title: Callable[[T], str]
) -> list[T]:
    """§8.3 ordering: most severe first, then by (localised) title; stable for equal keys."""
    return sorted(items, key=lambda i: (severity_rank(severity(i)), title(i).casefold()))
