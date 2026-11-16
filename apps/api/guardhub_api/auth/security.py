"""Auth primitives: argon2id passwords, JWT session tokens, TOTP. No HTTP or DB knowledge here.

- Password hashing is CPU-bound, so callers use the async wrappers (thread pool, §7.1).
- Session JWTs carry `mfa`. A pre-MFA token (mfa=false, 10 min) can only finish 2FA. Full
  access needs mfa=true (§9.1: 2FA is mandatory for the dashboard and admin).
- TOTP verification rejects reuse of an already accepted time step (replay protection).
"""

from __future__ import annotations

import asyncio
import secrets
import time
import uuid
from dataclasses import dataclass
from typing import Literal

import jwt
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # argon2id with library defaults (RFC 9106 low-memory profile)
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))  # equalises timing for unknown emails
JWT_ALG = "HS256"
ISSUER = "guardhub-api"
TOTP_ISSUER = "GuardHub"


async def hash_password(password: str) -> str:
    return await asyncio.to_thread(_hasher.hash, password)


async def verify_password(stored_hash: str | None, password: str) -> bool:
    def _verify() -> bool:
        try:
            return _hasher.verify(stored_hash or _DUMMY_HASH, password) and stored_hash is not None
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    return await asyncio.to_thread(_verify)


@dataclass(frozen=True, slots=True)
class SessionClaims:
    user_id: uuid.UUID
    role: Literal["user", "admin"]
    mfa: bool
    jti: str
    exp: int


def issue_session(*, user_id: uuid.UUID, role: str, mfa: bool, ttl_seconds: int) -> SessionClaims:
    return SessionClaims(
        user_id=user_id,
        role="admin" if role == "admin" else "user",
        mfa=mfa,
        jti=secrets.token_urlsafe(16),
        exp=int(time.time()) + ttl_seconds,
    )


def encode_session(secret: str, claims: SessionClaims) -> str:
    payload = {
        "sub": str(claims.user_id),
        "role": claims.role,
        "mfa": claims.mfa,
        "jti": claims.jti,
        "iat": int(time.time()),
        "exp": claims.exp,
        "iss": ISSUER,
    }
    return jwt.encode(payload, secret, algorithm=JWT_ALG)


def decode_session(secret: str, token: str) -> SessionClaims | None:
    try:
        data = jwt.decode(
            token,
            secret,
            algorithms=[JWT_ALG],
            issuer=ISSUER,
            options={"require": ["sub", "exp", "jti", "iss"]},
        )
        role = data.get("role")
        return SessionClaims(
            user_id=uuid.UUID(str(data["sub"])),
            role="admin" if role == "admin" else "user",
            mfa=data.get("mfa") is True,
            jti=str(data["jti"]),
            exp=int(data["exp"]),
        )
    except (jwt.PyJWTError, ValueError, KeyError):
        return None


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, email: str) -> str:
    return str(pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=TOTP_ISSUER))


def totp_matching_step(secret: str, code: str, *, now: float | None = None) -> int | None:
    """Return the accepted time step for `code` (±1 step of drift), or None if it doesn't match."""
    if not (len(code) == 6 and code.isdigit()):
        return None
    totp = pyotp.TOTP(secret)
    t = now if now is not None else time.time()
    current = int(t // totp.interval)
    for step in (current - 1, current, current + 1):
        if secrets.compare_digest(str(totp.generate_otp(step)), code):
            return step
    return None


COMMON_PASSWORDS = frozenset(
    {
        "password1234", "123456789012", "qwertyuiop12", "passwordpassword", "letmein12345",
        "iloveyou1234", "administrator", "welcome12345", "changeme1234", "guardhub1234",
    }
)  # fmt: skip


def password_problem(password: str, email: str) -> str | None:
    """Return a stable reason code if the password is unacceptable, else None."""
    if len(password) < 12:
        return "too_short"
    if len(password) > 128:
        return "too_long"
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or len(set(password)) < 5:
        return "too_common"
    local = email.split("@", 1)[0].lower()
    if len(local) >= 4 and local in lowered:
        return "contains_email"
    return None
