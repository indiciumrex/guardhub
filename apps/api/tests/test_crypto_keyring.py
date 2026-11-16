"""Keyring (DATA_ENCRYPTION_KEY rotation): encrypt with current, decrypt current → previous."""

from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

from guardhub_api.common.crypto import Cipher, DecryptionError, Keyring, parse_key, parse_key_list
from guardhub_api.config import Settings

OLD = b"o" * 32
NEW = b"n" * 32
OTHER = b"x" * 32


def b64(key: bytes) -> str:
    return base64.b64encode(key).decode()


def test_encrypts_with_current_key_only() -> None:
    ring = Keyring(NEW, [OLD])
    token = ring.encrypt("secret", b"aad")
    assert Cipher(NEW).decrypt(token, b"aad") == "secret"
    with pytest.raises(Exception):  # noqa: B017 — InvalidTag
        Cipher(OLD).decrypt(token, b"aad")
    assert ring.decrypt_with_index(token, b"aad") == ("secret", 0)


def test_reads_values_under_previous_keys_in_order() -> None:
    old_token = Cipher(OLD).encrypt("totp-seed", b"user-1")
    other_token = Cipher(OTHER).encrypt("hook", b"user-2")
    ring = Keyring(NEW, [OLD, OTHER])
    assert ring.decrypt_with_index(old_token, b"user-1") == ("totp-seed", 1)
    assert ring.decrypt_with_index(other_token, b"user-2") == ("hook", 2)
    assert ring.decrypt(old_token, b"user-1") == "totp-seed"


def test_existing_v1_ciphertext_stays_readable() -> None:
    legacy = Cipher(NEW).encrypt("DB_PASSWORD=****abcd", b"evidence-1")  # format before the keyring
    assert legacy.startswith("v1.")
    assert Keyring(NEW).decrypt(legacy, b"evidence-1") == "DB_PASSWORD=****abcd"


def test_wrong_key_is_an_error_never_garbage() -> None:
    token = Cipher(OTHER).encrypt("secret", b"aad")
    with pytest.raises(DecryptionError):
        Keyring(NEW, [OLD]).decrypt(token, b"aad")


def test_tampered_ciphertext_fails_with_every_key() -> None:
    token = Keyring(NEW, [OLD]).encrypt("secret", b"aad")
    tampered = token[:-2] + ("A" if token[-2] != "A" else "B") + token[-1]
    with pytest.raises(DecryptionError):
        Keyring(NEW, [OLD]).decrypt(tampered, b"aad")
    for bad in ("v2.abc", "v1.!!!", "v1.", "v1." + base64.urlsafe_b64encode(b"short").decode()):
        with pytest.raises(DecryptionError):
            Keyring(NEW).decrypt(bad, b"aad")


def test_aad_mismatch_fails_even_with_previous_key() -> None:
    token = Cipher(OLD).encrypt("secret", b"user-1")
    with pytest.raises(DecryptionError):
        Keyring(NEW, [OLD]).decrypt(token, b"user-2")


def test_duplicate_previous_keys_are_ignored() -> None:
    assert Keyring(NEW, [NEW, OLD, OLD]).size == 2


def test_key_parsing() -> None:
    assert parse_key(b64(NEW)) == NEW
    assert parse_key_list("") == []
    assert parse_key_list(f"{b64(OLD)},{b64(OTHER)}") == [OLD, OTHER]
    assert parse_key_list(f" {b64(OLD)} , {b64(OTHER)} ") == [OLD, OTHER]
    for bad in ("not base64!", b64(b"short"), b64(b"k" * 33)):
        with pytest.raises(ValueError):
            parse_key(bad)
    with pytest.raises(ValueError, match="key #2"):
        parse_key_list(f"{b64(OLD)},")  # a stray comma is refused, not silently skipped


def _settings(**overrides: str) -> Settings:
    env = {
        "database_url": "postgresql+asyncpg://t:t@127.0.0.1:1/t",
        "redis_url": "redis://127.0.0.1:1/0",
        "jwt_secret": "test-only-jwt-secret-0123456789abcdef0123456789",
        "hash_pepper": "test-only-hash-pepper-0123456789abcdef012345678",
        "data_encryption_key": b64(NEW),
    }
    env.update(overrides)
    return Settings(**env)  # type: ignore[arg-type]


def test_settings_keyring_and_validation() -> None:
    s = _settings(data_encryption_keys_previous=f"{b64(OLD)},{b64(OTHER)}")
    ring = s.keyring
    assert ring.size == 3
    assert ring.decrypt(Cipher(OTHER).encrypt("v", b"a"), b"a") == "v"
    assert _settings().keyring.size == 1  # PREVIOUS is optional
    with pytest.raises(ValidationError) as err:
        _settings(data_encryption_keys_previous=f"{b64(OLD)},{b64(b'short')}")
    assert b64(OLD) not in str(err.value)  # the key itself is never echoed
    with pytest.raises(ValidationError):
        _settings(data_encryption_key="change-me-base64-32-bytes")
