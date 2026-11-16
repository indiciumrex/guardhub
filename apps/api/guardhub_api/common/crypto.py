"""Cryptographic helpers: AES-256-GCM at rest, keyed hashing, and random tokens (§9.1).

- `Cipher` encrypts small sensitive values (TOTP secrets, evidence, Slack webhooks) with one key
  and a random 96-bit nonce. The stored format is `v1.<b64url(nonce|ciphertext)>`.
- `Keyring` is what the app uses: it ENCRYPTS with the current key only and DECRYPTS with the
  current key, then each previous key in order (key rotation, ops/runbooks/production.md).
  AES-GCM is authenticated, so a wrong key fails loudly instead of returning garbage; a value no
  key opens raises `DecryptionError` and is never silently ignored. The ciphertext carries no
  key id, so existing `v1.` values stay readable unchanged.
- `keyed_hash` is HMAC-SHA256 with the server pepper, used for client IPs and scan access
  tokens so the raw values are never stored.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from collections.abc import Sequence

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PREFIX = "v1."
_NONCE_BYTES = 12


class DecryptionError(ValueError):
    """No configured key opens this ciphertext (wrong/missing key, tampering or wrong AAD)."""


class Cipher:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self._aead = AESGCM(key)

    def encrypt(self, plaintext: str, associated_data: bytes = b"") -> str:
        nonce = secrets.token_bytes(12)
        ct = self._aead.encrypt(nonce, plaintext.encode("utf-8"), associated_data or None)
        return _PREFIX + base64.urlsafe_b64encode(nonce + ct).decode("ascii")

    def decrypt(self, token: str, associated_data: bytes = b"") -> str:
        nonce, ct = _split(token)
        return self._aead.decrypt(nonce, ct, associated_data or None).decode("utf-8")


def _split(token: str) -> tuple[bytes, bytes]:
    if not token.startswith(_PREFIX):
        raise DecryptionError("unknown ciphertext version")
    try:
        raw = base64.urlsafe_b64decode(token[len(_PREFIX) :].encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise DecryptionError("malformed ciphertext") from exc
    if len(raw) <= _NONCE_BYTES:
        raise DecryptionError("malformed ciphertext")
    return raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]


def parse_key(b64: str) -> bytes:
    """A base64 AES-256 key → 32 raw bytes. Raises ValueError (never echoing the value)."""
    try:
        key = base64.b64decode(b64.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("must be base64") from exc
    if len(key) != 32:
        raise ValueError("must decode to exactly 32 bytes (AES-256)")
    return key


def parse_key_list(csv: str) -> list[bytes]:
    """Comma-separated base64 keys (empty → []). Blank entries are refused, not skipped."""
    if not csv.strip():
        return []
    keys = []
    for i, part in enumerate(csv.split(",")):
        try:
            keys.append(parse_key(part))
        except ValueError as exc:
            raise ValueError(f"key #{i + 1}: {exc}") from None
    return keys


class Keyring:
    """Current key for new encryption; current + previous keys (in order) for decryption."""

    def __init__(self, current: bytes, previous: Sequence[bytes] = ()) -> None:
        keys = [current]
        for key in previous:
            if key not in keys:  # the old key may still be listed right after a rotation
                keys.append(key)
        self._ciphers = [Cipher(k) for k in keys]

    @classmethod
    def from_b64(cls, current: str, previous_csv: str = "") -> Keyring:
        return cls(parse_key(current), parse_key_list(previous_csv))

    @property
    def size(self) -> int:
        return len(self._ciphers)

    def encrypt(self, plaintext: str, associated_data: bytes = b"") -> str:
        return self._ciphers[0].encrypt(plaintext, associated_data)

    def decrypt(self, token: str, associated_data: bytes = b"") -> str:
        return self.decrypt_with_index(token, associated_data)[0]

    def decrypt_with_index(self, token: str, associated_data: bytes = b"") -> tuple[str, int]:
        """Plaintext and which key opened it: 0 = current, 1.. = DATA_ENCRYPTION_KEYS_PREVIOUS."""
        nonce, ct = _split(token)
        for index, cipher in enumerate(self._ciphers):
            try:
                plain = cipher._aead.decrypt(nonce, ct, associated_data or None)
            except InvalidTag:
                continue
            return plain.decode("utf-8"), index
        raise DecryptionError("no configured key can decrypt this value")


def keyed_hash(pepper: str, value: str) -> str:
    return hmac.new(pepper.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def random_token(prefix: str, nbytes: int = 24) -> str:
    return f"{prefix}_{secrets.token_urlsafe(nbytes)}"


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
