"""Module registry: reads and toggles feature flags in the `modules` table.

Decides which checks a scan may run (Python decides *what* to scan, §3). Ordering follows
check-ids.json so scans are deterministic. Every toggle is audited. A check module can only
be switched on when the validation lab measured it and it met the gate (modules/accuracy.py).
"""

from __future__ import annotations

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.common import audit
from guardhub_api.common.errors import NotFoundError, UnprocessableError
from guardhub_api.db.models import Module
from guardhub_api.findings.contract_gen import CHECK_IDS, REPO_CHECK_IDS, SITE_CHECK_IDS
from guardhub_api.modules import accuracy
from guardhub_api.modules.accuracy import CheckAccuracy


class ModuleView(BaseModel):
    key: str
    name: str
    category: str
    enabled_global: bool
    min_plan: str
    # Check modules only: the lab's measurement (None = never measured, cannot be enabled).
    accuracy: CheckAccuracy | None = None


def _view(m: Module) -> ModuleView:
    return ModuleView(
        key=m.key,
        name=m.name,
        category=m.category,
        enabled_global=m.enabled_global,
        min_plan=m.min_plan,
        accuracy=accuracy.measured(m.key) if m.key in CHECK_IDS else None,
    )


async def list_modules(session: AsyncSession) -> list[ModuleView]:
    rows = (await session.execute(select(Module).order_by(Module.key))).scalars().all()
    return [_view(m) for m in rows]


async def enabled_check_ids(session: AsyncSession, target: str = "site") -> list[str]:
    """Enabled checks for a site scan, or for a repository scan (target="repo", ADR-0006)."""
    rows = await session.execute(select(Module.key).where(Module.enabled_global.is_(True)))
    enabled = set(rows.scalars().all())
    ids = REPO_CHECK_IDS if target == "repo" else SITE_CHECK_IDS
    return [cid for cid in ids if cid in enabled]


async def set_enabled(session: AsyncSession, *, key: str, enabled: bool, actor: str) -> ModuleView:
    module = (await session.execute(select(Module).where(Module.key == key))).scalar_one_or_none()
    if module is None:
        raise NotFoundError("module_not_found", "Unknown module.")
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
