"""AIProvider seam (§8.4): a single interface for optional AI enrichment.

Without a configured key the provider is `NoopAIProvider`. Every method returns its input
unchanged or None immediately, so scanning, reports and health work identically without AI.
Real providers arrive in Phase 4 (§11) behind this same interface. Callers must always treat the
result as optional.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel

from guardhub_api.config import Settings


class AIStatus(BaseModel):
    provider: str | None
    enabled: bool
    active: bool


@runtime_checkable
class AIProvider(Protocol):
    name: str

    @property
    def active(self) -> bool: ...

    async def summarize_report(self, plain_report: str, locale: str) -> str | None:
        """Optional executive summary of an already plain-language report; None = unavailable."""
        ...

    async def detect_anomalies(self, metrics: dict[str, float]) -> list[str]:
        """Optional anomaly hints over health metrics; empty = none/unavailable."""
        ...


class NoopAIProvider:
    """The default provider. It does nothing, never fails, and never blocks the core path."""

    name = "noop"

    @property
    def active(self) -> bool:
        return False

    async def summarize_report(self, plain_report: str, locale: str) -> str | None:
        return None

    async def detect_anomalies(self, metrics: dict[str, float]) -> list[str]:
        return []


def get_provider(settings: Settings) -> AIProvider:
    """Phase 4 will map `settings.ai_provider` + key to a concrete provider. Until then it's no-op,
    even if a key is present, because the MVP ships the seam only (§8.4)."""
    return NoopAIProvider()


def status(settings: Settings) -> AIStatus:
    configured = bool(settings.ai_provider and settings.ai_api_key.get_secret_value())
    provider = get_provider(settings)
    return AIStatus(provider=settings.ai_provider or None, enabled=configured, active=provider.active)
