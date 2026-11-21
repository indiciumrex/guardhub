"""GitHub integration request/response models (ADR-0006)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class InstallationView(BaseModel):
    id: uuid.UUID
    account_login: str
    account_type: str
    created_at: datetime


class GitHubStatus(BaseModel):
    configured: bool
    installations: list[InstallationView]


class ConnectStart(BaseModel):
    install_url: str


class ConnectComplete(BaseModel):
    code: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_-]+$")
    installation_id: int = Field(gt=0, lt=2**53)
    state: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class RepoView(BaseModel):
    repo_id: int
    full_name: str
    private: bool
    project_id: uuid.UUID | None  # already added as a GuardHub project


class AddRepoRequest(BaseModel):
    repo_id: int = Field(gt=0, lt=2**53)
