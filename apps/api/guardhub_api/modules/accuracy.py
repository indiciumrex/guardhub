"""Measured check accuracy: the gate that decides whether a check module may be switched ON.

- Passive checks, Gate L (Phase 2): packages/shared/accuracy.json, written by the validation lab.
- Active checks, Gate M (ADR-0008 §9): docs/accuracy-active/scorecard.json, written by CI's
  `scanner activelab` and compared with the ZAP oracle. Active checks are never in accuracy.json,
  so they are judged by their own lab only (the founder's checkpoint is a separate lock).

A module may be switched ON only when its lab measured it and it met the gate (precision, recall,
sample size, a clean target, no errors). It fails closed: a missing or unreadable file, or a check
missing from it, counts as "not measured". Switching a module OFF is never blocked. Modules that
are not checks are not gated here.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from guardhub_api.config import get_settings
from guardhub_api.findings.contract_gen import ACTIVE_CHECK_IDS
from guardhub_api.modules import scorecards


class CheckAccuracy(BaseModel):
    model_config = ConfigDict(extra="ignore")

    meets_gate: bool
    precision: float | None
    recall: float | None
    recall_all: float | None
    tp: int
    fp: int
    fn: int
    fn_outside: int
    targets: int


class _GateFile(BaseModel):
    model_config = ConfigDict(extra="ignore")

    version: int
    checks: dict[str, CheckAccuracy]


@lru_cache(maxsize=4)
def _load(path: Path) -> dict[str, CheckAccuracy]:
    try:
        return _GateFile.model_validate(json.loads(path.read_text(encoding="utf-8"))).checks
    except (OSError, ValueError, ValidationError):
        return {}


def measured(check_id: str) -> CheckAccuracy | None:
    """The lab's measurement of check_id, or None when it was never measured."""
    return _load(get_settings().shared_dir / "accuracy.json").get(check_id)


def may_enable(check_id: str) -> bool:
    if check_id in ACTIVE_CHECK_IDS:
        g = scorecards.gate_for(check_id, active=True)
        return g.measured and g.meets_gate
    m = measured(check_id)
    return m is not None and m.meets_gate
