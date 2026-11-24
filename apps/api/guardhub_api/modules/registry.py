"""Module registry: reads and toggles feature flags in the `modules` table.

Decides which checks a scan may run (Python decides *what* to scan, §3). Ordering follows
check-ids.json so scans are deterministic. Every toggle is audited. A check module can only
be switched on when the validation lab measured it and it met the gate (modules/accuracy.py).
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.common import audit
from guardhub_api.common.errors import NotFoundError, UnprocessableError
from guardhub_api.config import get_settings
from guardhub_api.db.models import Module
from guardhub_api.findings.contract_gen import ACTIVE_CHECK_IDS, CHECK_IDS, REPO_CHECK_IDS, SITE_CHECK_IDS
from guardhub_api.modules import accuracy, scorecards
from guardhub_api.modules.accuracy import CheckAccuracy

Plan = Literal["free", "pro", "agency"]
PLANS: tuple[str, ...] = ("free", "pro", "agency")


class ModuleView(BaseModel):
    key: str
    name: str
    category: str
    enabled_global: bool
    min_plan: str
    # Check modules only: the lab's measurement (None = never measured, cannot be enabled).
    accuracy: CheckAccuracy | None = None
    maintenance: bool = False
    # active: on and in new scans; maintenance: on but kept out of new scans; disabled: off
    status: Literal["active", "maintenance", "disabled"] = "disabled"
    stage: Literal["ga", "beta"] = "ga"  # beta: Phase 4B active checks (founder checkpoint)
    is_check: bool = False
    gate: scorecards.GateView | None = None  # Gate L (passive) or M (active) scorecard numbers
    # why switching it ON is refused right now (None: it may be switched on)
    enable_blocked: str | None = None


def blocked_reason(key: str) -> str | None:
    """The rule that refuses switching `key` on now: the same order set_enabled applies."""
    if key in ACTIVE_CHECK_IDS and not get_settings().active_testing_approved:
        return "active_testing_not_approved"
    if key in CHECK_IDS:
        m = accuracy.measured(key)
        if m is None:
            return "module_not_measured"
        if not m.meets_gate:
            return "gate_not_met"
    return None


def _view(m: Module) -> ModuleView:
    is_check = m.key in CHECK_IDS
    status: Literal["active", "maintenance", "disabled"] = "disabled"
    if m.enabled_global:
        status = "maintenance" if m.maintenance else "active"
    return ModuleView(
        key=m.key,
        name=m.name,
        category=m.category,
        enabled_global=m.enabled_global,
        min_plan=m.min_plan,
        accuracy=accuracy.measured(m.key) if is_check else None,
        maintenance=m.maintenance,
        status=status,
        stage="beta" if m.key in ACTIVE_CHECK_IDS else "ga",
        is_check=is_check,
        gate=scorecards.gate_for(m.key, active=m.key in ACTIVE_CHECK_IDS) if is_check else None,
        enable_blocked=None if m.enabled_global else blocked_reason(m.key),
    )


async def list_modules(session: AsyncSession) -> list[ModuleView]:
    rows = (await session.execute(select(Module).order_by(Module.key))).scalars().all()
    return [_view(m) for m in rows]


async def enabled_check_ids(session: AsyncSession, target: str = "site") -> list[str]:
    """Enabled checks for a site scan, or for a repository scan (target="repo", ADR-0006)."""
    rows = await session.execute(
        select(Module.key).where(Module.enabled_global.is_(True), Module.maintenance.is_(False))
    )
    enabled = set(rows.scalars().all())
    ids = REPO_CHECK_IDS if target == "repo" else SITE_CHECK_IDS
    return [cid for cid in ids if cid in enabled]


async def set_enabled(session: AsyncSession, *, key: str, enabled: bool, actor: str) -> ModuleView:
    module = (await session.execute(select(Module).where(Module.key == key))).scalar_one_or_none()
    if module is None:
        raise NotFoundError("module_not_found", "Unknown module.")
    if enabled and key in ACTIVE_CHECK_IDS and not get_settings().active_testing_approved:
        raise UnprocessableError(
            "active_testing_not_approved",
            "Active tests stay off until the founder's checkpoint (ADR-0008 §8).",
        )
    if enabled and not module.enabled_global and key in CHECK_IDS and not accuracy.may_enable(key):
        raise UnprocessableError(
            "module_not_measured",
            "This check has no measured accuracy that meets the gate yet (see docs/accuracy).",
        )
    previous = module.enabled_global
    module.enabled_global = enabled
    await session.flush()
    await audit.record(
        session,
        actor=actor,
        action="module.toggle",
        target=key,
        metadata={"from": str(previous).lower(), "to": str(enabled).lower()},
    )
    return _view(module)


async def set_config(
    session: AsyncSession,
    *,
    key: str,
    actor: str,
    maintenance: bool | None = None,
    min_plan: str | None = None,
) -> ModuleView:
    """Maintenance mode and minimum plan (audited as module.config, before and after)."""
    module = (await session.execute(select(Module).where(Module.key == key))).scalar_one_or_none()
    if module is None:
        raise NotFoundError("module_not_found", "Unknown module.")
    if min_plan is not None and min_plan not in PLANS:
        raise UnprocessableError("invalid_plan", "Unknown plan.")
    changes: dict[str, str] = {}
    if maintenance is not None and maintenance != module.maintenance:
        changes["maintenance_from"] = str(module.maintenance).lower()
        changes["maintenance_to"] = str(maintenance).lower()
        module.maintenance = maintenance
    if min_plan is not None and min_plan != module.min_plan:
        changes["plan_from"], changes["plan_to"] = module.min_plan, min_plan
        module.min_plan = min_plan
    if changes:
        await session.flush()
        await audit.record(session, actor=actor, action="module.config", target=key, metadata=changes)
    return _view(module)
