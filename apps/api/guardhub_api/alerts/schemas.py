"""Notification settings / history request and response models (docs/architecture.md §8.4)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Channel = Literal["email", "slack"]


class NotificationSettingsView(BaseModel):
    """The Slack webhook URL is a secret: only whether one is configured is ever returned."""

    email_enabled: bool
    notify_new: bool
    notify_regression: bool
    notify_fixed: bool
    slack_configured: bool
    email: str


class UpdateNotificationSettings(BaseModel):
    """`slack_webhook_url` omitted = keep the stored one, null = remove it."""

    model_config = ConfigDict(extra="forbid")

    email_enabled: bool
    notify_new: bool
    notify_regression: bool
    notify_fixed: bool
    slack_webhook_url: str | None = Field(default=None, max_length=300)


class TestNotificationRequest(BaseModel):
    channel: Channel


class TestNotificationQueued(BaseModel):
    status: Literal["queued"] = "queued"


class NotificationHistoryItem(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    project_id: uuid.UUID | None
    channel: Channel
    status: Literal["pending", "sent", "failed", "skipped"]
    new_count: int
    regression_count: int
    fixed_count: int
    created_at: datetime
    sent_at: datetime | None
