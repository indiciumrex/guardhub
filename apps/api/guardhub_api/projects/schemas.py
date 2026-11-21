"""Project request/response models (docs/architecture.md §4.4)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from guardhub_api.projects.verification import VerificationInstructions
from guardhub_api.scans.schemas import ScanSummary


class CreateProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    target_url: str = Field(min_length=1, max_length=2048)


class UpdateProjectRequest(BaseModel):
    """Rename and/or set the monitoring schedule (§4.4, §8.2). At least one field is required."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    scan_frequency: Literal["off", "daily", "weekly"] | None = None

    @model_validator(mode="after")
    def _something_to_change(self) -> UpdateProjectRequest:
        if self.name is None and self.scan_frequency is None:
            raise ValueError("send name and/or scan_frequency")
        if self.name is not None and not self.name.strip():
            raise ValueError("name must not be blank")
        return self


class ClaimScanRequest(BaseModel):
    scan_id: uuid.UUID
    access_token: str = Field(min_length=8, max_length=128)
    name: str = Field(min_length=1, max_length=120)


class ProjectView(BaseModel):
    id: uuid.UUID
    name: str
    kind: Literal["site", "repo"] = "site"
    repo_full_name: str | None = None  # kind "repo": owner/name on GitHub (ADR-0006)
    target_url: str
    verified: bool
    ownership_verified_at: datetime | None
    verification: VerificationInstructions
    last_scan: ScanSummary | None
    scan_frequency: Literal["off", "daily", "weekly"]
    next_scan_at: datetime | None
    schedule_paused_reason: Literal["ownership_lost"] | None
    created_at: datetime
