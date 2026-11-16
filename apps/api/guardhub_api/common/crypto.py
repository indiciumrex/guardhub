"""Cryptographic helpers: AES-256-GCM at rest, keyed hashing, and random tokens (§9.1).

- `Cipher` encrypts small sensitive values (TOTP secrets, evidence) with a random 96-bit nonce.
  The stored format is `v1.<b64url(nonce|ciphertext)>`.
- `keyed_hash` is HMAC-SHA256 with the server pepper, used for client IPs and scan access
  tokens so the raw values are never stored.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PREFIX = "v1."


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
        if not token.startswith(_PREFIX):
            raise ValueError("unknown ciphertext version")
        raw = base64.urlsafe_b64decode(token[len(_PREFIX) :].encode("ascii"))
        nonce, ct = raw[:12], raw[12:]
        return self._aead.decrypt(nonce, ct, associated_data or None).decode("utf-8")


def keyed_hash(pepper: str, value: str) -> str:
    return hmac.new(pepper.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def random_token(prefix: str, nbytes: int = 24) -> str:
    return f"{prefix}_{secrets.token_urlsafe(nbytes)}"


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
