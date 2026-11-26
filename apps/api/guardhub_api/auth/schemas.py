"""Auth request/response models (docs/architecture.md §4.3)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    email: EmailStr = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)
    locale: str = Field(default="en", max_length=10)


class LoginRequest(BaseModel):
    email: EmailStr = Field(max_length=254)
    password: str = Field(min_length=1, max_length=256)


class TotpVerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class UpdateMeRequest(BaseModel):
    locale: str | None = Field(default=None, max_length=10)
    # "" clears the name; None leaves it unchanged.
    display_name: str | None = Field(default=None, max_length=80)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")  # a current authenticator code


class UserView(BaseModel):
    id: uuid.UUID
    email: str
    role: Literal["user", "admin"]
    locale: str
    display_name: str | None = None
    totp_enabled: bool
    mfa_complete: bool
    created_at: datetime
    password_changed_at: datetime | None = None


class MfaState(BaseModel):
    mfa: Literal["setup_required", "required"]


class RegisterResponse(MfaState):
    user: UserView


class TotpSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str


class SessionResponse(BaseModel):
    user: UserView
    recovery_codes: list[str] | None = None  # only right after two-factor was first enabled


class RecoveryCodeRequest(BaseModel):
    code: str = Field(min_length=10, max_length=20, pattern=r"^[A-Za-z0-9 -]+$")


class RecoveryStatus(BaseModel):
    remaining: int


class RecoveryCodes(BaseModel):
    codes: list[str]
