"""The lab scorecards behind the module gates, for the admin's Module Center (read-only).

- Gate L (passive checks): docs/accuracy/scorecard.json, written by CI's `scanner lab`.
- Gate M (active checks, ADR-0008 §9): docs/accuracy-active/scorecard.json, written by CI's
  `scanner activelab` and compared with the ZAP oracle.

Both files are generated in CI and committed only when they match a CI measurement (never edited
by hand). The API image carries copies next to packages/shared (apps/api/Dockerfile). The ON
switch is decided by modules/accuracy.py: Gate L for passive checks, and this Gate M scorecard for
active checks (plus the founder's checkpoint). A missing or unreadable file means "not measured",
so an active check cannot be switched on without it.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, ConfigDict, ValidationError

from guardhub_api.config import get_settings


class Measurement(BaseModel):
    model_config = ConfigDict(extra="ignore")

    check_id: str
    targets: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    fn_outside: int = 0
    errors: int = 0
    precision: float | None = None
    recall: float | None = None
    recall_all: float | None = None
    meets_gate: bool = False


class _Scorecard(BaseModel):
    model_config = ConfigDict(extra="ignore")

    source: str = ""
    checks: list[Measurement] = []


class GateView(BaseModel):
    gate: str  # "L" (passive lab) or "M" (active lab)
    measured: bool
    meets_gate: bool
    source: str  # git revision the lab measured ("" when not measured)
    precision: float | None = None
    recall: float | None = None
    false_positive_rate: float | None = None  # fp / (tp + fp) in the lab
    tp: int = 0
    fp: int = 0
    fn: int = 0
    targets: int = 0


def _docs_dir() -> Path:
    # <root>/packages/shared -> <root>/docs (the repository and the API image use the same layout)
    return get_settings().shared_dir.parent.parent / "docs"


@lru_cache(maxsize=4)
def _load(path: Path) -> tuple[str, dict[str, Measurement]]:
    try:
        card = _Scorecard.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError, ValidationError):
        return "", {}
    return card.source, {m.check_id: m for m in card.checks}


def gate_for(check_id: str, *, active: bool) -> GateView:
    gate = "M" if active else "L"
    path = _docs_dir() / ("accuracy-active" if active else "accuracy") / "scorecard.json"
    source, checks = _load(path)
    m = checks.get(check_id)
    if m is None:
        return GateView(gate=gate, measured=False, meets_gate=False, source="")
    positives = m.tp + m.fp
    return GateView(
        gate=gate,
        measured=True,
        meets_gate=m.meets_gate,
        source=source,
        precision=m.precision,
        recall=m.recall,
        false_positive_rate=(m.fp / positives) if positives else None,
        tp=m.tp,
        fp=m.fp,
        fn=m.fn,
        targets=m.targets,
    )
