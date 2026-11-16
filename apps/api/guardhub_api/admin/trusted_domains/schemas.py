"""Trusted-domain request/response models (docs/architecture.md §8.5)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from guardhub_api.projects.verification import VerificationInstructions

TrustedDomainStatus = Literal["pending", "active", "suspended", "revoked"]


class AddTrustedDomainRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)


class TrustedDomainView(BaseModel):
    id: uuid.UUID
    host: str
    target_origin: str
    status: TrustedDomainStatus
    verification: VerificationInstructions
    method: str | None
    verified_at: datetime | None
    last_checked_at: datetime | None
    suspended_at: datetime | None
    created_at: datetime
