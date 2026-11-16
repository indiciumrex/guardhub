"""Pydantic response models for scans (docs/architecture.md §4.4)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from guardhub_api.findings.contract_gen import EvidenceKind, Severity


class ChallengeRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)


ScanStatus = Literal["queued", "running", "done", "failed"]
CheckStatus = Literal["queued", "running", "done", "failed"]


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanSummary(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID | None
    target_url: str
    status: ScanStatus
    score: int | None
    finding_counts: SeverityCounts
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    error: str | None


class ProgressItem(BaseModel):
    check_id: str
    name: str
    status: CheckStatus


class EvidenceView(BaseModel):
    kind: EvidenceKind
    location: str
    redacted_payload: str


class FindingView(BaseModel):
    id: uuid.UUID
    check_id: str
    finding_key: str
    severity: Severity
    title: str
    summary: str
    why: str
    fix: str
    evidence: EvidenceView | None
    status: Literal["open", "fixed", "ignored"]


class ScanView(ScanSummary):
    progress: list[ProgressItem]
    findings: list[FindingView]
