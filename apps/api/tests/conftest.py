"""Test configuration. Sets a deterministic, clearly fake environment BEFORE the app is imported.

These values are test-only, never deployed, and exist only so Settings validation passes.
Integration tests (tests/integration) also need GUARDHUB_TEST_DATABASE_URL / _REDIS_URL and are
skipped without them.
"""

from __future__ import annotations

import base64
import os

os.environ.setdefault(
    "DATABASE_URL", os.environ.get("GUARDHUB_TEST_DATABASE_URL", "postgresql+asyncpg://t:t@127.0.0.1:1/t")
)
os.environ.setdefault("REDIS_URL", os.environ.get("GUARDHUB_TEST_REDIS_URL", "redis://127.0.0.1:1/0"))
os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-0123456789abcdef0123456789")
os.environ.setdefault("HASH_PEPPER", "test-only-hash-pepper-0123456789abcdef012345678")
os.environ.setdefault("DATA_ENCRYPTION_KEY", base64.b64encode(b"t" * 32).decode())
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("TRUSTED_PROXY_HOPS", "0")
os.environ.setdefault("LOG_LEVEL", "warning")
os.environ["SENTRY_DSN"] = ""  # error tracking stays off in tests, whatever the developer's shell has
