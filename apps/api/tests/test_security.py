from __future__ import annotations

import base64
import time
import uuid

import jwt
import pyotp
import pytest
from pydantic import ValidationError

from guardhub_api.auth.security import (
    CLOCK_SKEW_LEEWAY_SECONDS,
    decode_session,
    encode_session,
    hash_password,
    issue_session,
    password_problem,
    totp_matching_step,
    verify_password,
)
from guardhub_api.common.crypto import Cipher, keyed_hash, random_token
from guardhub_api.config import Settings

SECRET = "test-only-jwt-secret-0123456789abcdef0123456789"


async def test_password_hash_roundtrip_and_unknown_user() -> None:
    hashed = await hash_password("correct horse battery staple")
    assert hashed.startswith("$argon2id$")
    assert await verify_password(hashed, "correct horse battery staple")
    assert not await verify_password(hashed, "wrong password!!")
    assert not await verify_password(None, "anything at all")  # unknown email: still constant work


@pytest.mark.parametrize(
    ("password", "problem"),
    [
        ("short", "too_short"),
        ("x" * 129, "too_long"),
        ("password1234", "too_common"),
        ("aaaaaaaaaaaaaaa", "too_common"),
        ("alice-is-great-2026", "contains_email"),
        ("Tr0ub4dor&3-horse", None),
    ],
)
def test_password_policy(password: str, problem: str | None) -> None:
    assert password_problem(password, "alice@example.com") == problem


def test_session_token_roundtrip_and_tamper() -> None:
    claims = issue_session(user_id=uuid.uuid4(), role="admin", mfa=True, ttl_seconds=60)
    token = encode_session(SECRET, claims)
    decoded = decode_session(SECRET, token)
    assert decoded == claims
    assert decode_session(SECRET + "x", token) is None
    header, payload, sig = token.split(".")
    assert decode_session(SECRET, f"{header}.{payload}.{sig[::-1]}") is None


def test_expired_and_alg_none_tokens_rejected() -> None:
    expired = -(CLOCK_SKEW_LEEWAY_SECONDS + 5)
    claims = issue_session(user_id=uuid.uuid4(), role="user", mfa=False, ttl_seconds=expired)
    assert decode_session(SECRET, encode_session(SECRET, claims)) is None
    unsigned = (
        base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        + "."
        + base64.urlsafe_b64encode(
            f'{{"sub":"{uuid.uuid4()}","role":"admin","mfa":true,"jti":"x","exp":{int(time.time()) + 60},'
            f'"iss":"guardhub-api"}}'.encode()
        )
        .rstrip(b"=")
        .decode()
        + "."
    )
    assert decode_session(SECRET, unsigned) is None


def test_small_clock_skew_tolerated_large_skew_rejected() -> None:
    """A token stamped by a host whose clock is slightly ahead (NTP step, VM resync) still works."""
    now = int(time.time())

    def token(iat: int) -> str:
        payload = {"sub": str(uuid.uuid4()), "role": "user", "mfa": False, "jti": "j", "iss": "guardhub-api"}
        return jwt.encode({**payload, "iat": iat, "exp": iat + 600}, SECRET, algorithm="HS256")

    assert decode_session(SECRET, token(now + 2)) is not None
    assert decode_session(SECRET, token(now + CLOCK_SKEW_LEEWAY_SECONDS + 60)) is None


def test_unknown_role_downgrades_to_user() -> None:
    claims = issue_session(user_id=uuid.uuid4(), role="superuser", mfa=True, ttl_seconds=60)
    assert claims.role == "user"


def test_totp_matching_step_window() -> None:
    secret = pyotp.random_base32()
    now = 1_800_000_000.0
    totp = pyotp.TOTP(secret)
    step = int(now // 30)
    assert totp_matching_step(secret, totp.at(now), now=now) == step
    assert totp_matching_step(secret, totp.at(now - 30), now=now) == step - 1
    assert totp_matching_step(secret, totp.at(now - 90), now=now) is None
    assert totp_matching_step(secret, "12a456", now=now) is None
    assert totp_matching_step(secret, "1234567", now=now) is None


def test_cipher_roundtrip_tamper_and_aad() -> None:
    cipher = Cipher(b"k" * 32)
    token = cipher.encrypt("DB_PASSWORD=****abcd", associated_data=b"evidence-1")
    assert token.startswith("v1.")
    assert "abcd" not in token
    assert cipher.decrypt(token, associated_data=b"evidence-1") == "DB_PASSWORD=****abcd"
    with pytest.raises(Exception):  # noqa: B017 — InvalidTag; any failure is acceptable
        cipher.decrypt(token, associated_data=b"evidence-2")
    tampered = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
    with pytest.raises(Exception):  # noqa: B017
        cipher.decrypt(tampered, associated_data=b"evidence-1")
    assert cipher.encrypt("same") != cipher.encrypt("same")  # random nonce


def test_keyed_hash_and_tokens() -> None:
    assert keyed_hash("p1", "1.2.3.4") != keyed_hash("p2", "1.2.3.4")
    assert len(keyed_hash("p", "x")) == 64
    tok = random_token("ghs", 32)
    assert tok.startswith("ghs_") and len(tok) > 40


@pytest.mark.parametrize(
    "overrides",
    [
        {"jwt_secret": "change-me-jwt-secret"},
        {"jwt_secret": "short"},
        {"hash_pepper": "change-me-hash-pepper-change-me-hash-pepper"},
        {"data_encryption_key": "change-me-base64-32-bytes"},
        {"data_encryption_key": base64.b64encode(b"x" * 16).decode()},
    ],
)
def test_settings_refuse_placeholder_or_weak_secrets(overrides: dict[str, str]) -> None:
    base = {
        "database_url": "postgresql+asyncpg://a:b@h/d",
        "redis_url": "redis://h:6379/0",
        "jwt_secret": "a" * 40,
        "hash_pepper": "b" * 40,
        "data_encryption_key": base64.b64encode(b"k" * 32).decode(),
    }
    with pytest.raises(ValidationError):
        Settings(**{**base, **overrides})
