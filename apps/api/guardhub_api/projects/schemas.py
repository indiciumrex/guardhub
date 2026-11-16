"""Project request/response models (docs/architecture.md §4.4)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from guardhub_api.projects.verification import VerificationInstructions
from guardhub_api.scans.schemas import ScanSummary


class CreateProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    target_url: str = Field(min_length=1, max_length=2048)


class UpdateProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class ClaimScanRequest(BaseModel):
    scan_id: uuid.UUID
    access_token: str = Field(min_length=8, max_length=128)
    name: str = Field(min_length=1, max_length=120)


class ProjectView(BaseModel):
    id: uuid.UUID
    name: str
    target_url: str
    verified: bool
    ownership_verified_at: datetime | None
    verification: VerificationInstructions
    last_scan: ScanSummary | None
    created_at: datetime
