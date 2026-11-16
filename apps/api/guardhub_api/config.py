"""Application settings loaded from environment variables (Pydantic Settings).

Secrets come ONLY from the environment (§7.1, §9.1); there are no defaults for secrets, and
weak or placeholder values are refused at startup.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from guardhub_api.common.crypto import Keyring, parse_key, parse_key_list

_PLACEHOLDER_MARK = "change-me"


def _default_shared_dir() -> Path:
    # repo layout: <root>/apps/api/guardhub_api/config.py → <root>/packages/shared
    return Path(__file__).resolve().parents[3] / "packages" / "shared"


class Settings(BaseSettings):
    """Runtime configuration. See .env.example for documentation of each value."""

    model_config = SettingsConfigDict(env_file=None, extra="ignore", case_sensitive=False)

    database_url: SecretStr = Field(description="postgresql+asyncpg:// URL for the RLS-bound app role")
    redis_url: SecretStr = Field(description="redis:// URL")
    jwt_secret: SecretStr
    data_encryption_key: SecretStr
    # Old keys, comma-separated, used ONLY to decrypt values not yet re-encrypted
    # (python -m guardhub_api.ops.rotate_encryption_key). Empty outside a rotation window.
    data_encryption_keys_previous: SecretStr = SecretStr("")
    hash_pepper: SecretStr

    public_base_url: str = "http://localhost:3000"
    cookie_secure: bool = True
    trusted_proxy_hops: int = Field(default=1, ge=0, le=5)
    shared_dir: Path = Field(default_factory=_default_shared_dir)
    log_level: str = "info"

    session_ttl_seconds: int = 8 * 3600
    pre_mfa_ttl_seconds: int = 10 * 60
    scan_deadline_seconds: int = Field(default=180, ge=30, le=300)
    verify_timeout_seconds: float = Field(default=25.0, ge=5, le=60)
    challenge_ttl_hours: int = 24

    ai_provider: str = ""
    ai_api_key: SecretStr = SecretStr("")

    # Mirrors the scanner's allowlist: only for the local e2e demo target. Empty in production.
    scanner_allow_private_hosts: str = ""

    # Scheduled monitoring (docs/architecture.md §8.2). Small numbers: the host is shared (§7.2).
    scheduler_batch: int = Field(default=10, ge=1, le=100)
    scheduler_max_inflight: int = Field(default=2, ge=1, le=50)

    # Alert e-mail (§8.4). Empty SMTP_HOST = e-mail alerts are recorded as skipped.
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from: str = ""
    smtp_security: Literal["starttls", "tls", "none"] = "starttls"
    # Plaintext SMTP is allowed ONLY for these hosts (a local sink such as mailpit), never by default.
    smtp_insecure_hosts: str = ""
    smtp_timeout_seconds: float = Field(default=15.0, ge=1, le=60)

    @property
    def private_host_allowlist(self) -> frozenset[str]:
        return frozenset(h.strip().lower() for h in self.scanner_allow_private_hosts.split(",") if h.strip())

    @property
    def smtp_insecure_allowlist(self) -> frozenset[str]:
        return frozenset(h.strip().lower() for h in self.smtp_insecure_hosts.split(",") if h.strip())

    @model_validator(mode="after")
    def _smtp_is_safe(self) -> Settings:
        if not self.smtp_host:
            return self
        host = self.smtp_host.strip().lower()
        if self.smtp_security == "none" and host not in self.smtp_insecure_allowlist:
            raise ValueError("SMTP_SECURITY=none is only allowed for a host listed in SMTP_INSECURE_HOSTS")
        if self.smtp_security == "none" and self.smtp_username:
            raise ValueError("SMTP credentials are never sent without TLS (SMTP_SECURITY=none)")
        if not self.smtp_from.strip() or any(c in self.smtp_from for c in "\r\n"):
            raise ValueError("SMTP_FROM must be set (one line) when SMTP_HOST is set")
        return self

    @field_validator("jwt_secret", "hash_pepper")
    @classmethod
    def _strong_secret(cls, v: SecretStr) -> SecretStr:
        raw = v.get_secret_value()
        if _PLACEHOLDER_MARK in raw or len(raw) < 32:
            raise ValueError("must be a real random secret of at least 32 characters")
        return v

    @field_validator("data_encryption_key")
    @classmethod
    def _aes_key(cls, v: SecretStr) -> SecretStr:
        parse_key(v.get_secret_value())
        return v

    @field_validator("data_encryption_keys_previous")
    @classmethod
    def _aes_key_list(cls, v: SecretStr) -> SecretStr:
        parse_key_list(v.get_secret_value())
        return v

    @property
    def encryption_key_bytes(self) -> bytes:
        """The CURRENT key only. Prefer `keyring` (it can also read values under previous keys)."""
        return parse_key(self.data_encryption_key.get_secret_value())

    @property
    def keyring(self) -> Keyring:
        return Keyring(
            self.encryption_key_bytes, parse_key_list(self.data_encryption_keys_previous.get_secret_value())
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
