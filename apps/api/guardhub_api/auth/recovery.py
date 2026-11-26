"""Two-factor recovery (Admin Panel gaps, 2026-11-26).

- Recovery codes: ten single-use codes (`xxxxx-xxxxx`, about 49 bits each), created when two-
  factor sign-in is first set up, shown once, stored as keyed hashes. A code replaces the
  authenticator code once at sign-in, under the same rate limit (5 tries per 5 minutes).
  Regenerating them needs a current authenticator code and voids the old ones.
- Admin reset: another admin (never yourself), who confirms with their own current
  authenticator code, can clear an account's two-factor setup. It ends every session of that
  account and deletes its recovery codes; the account must sign in with its password and set up
  two-factor again. A stolen admin session cookie alone is not enough.
Every step is audited.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from guardhub_api.auth.security import totp_matching_step
from guardhub_api.common.crypto import keyed_hash
from guardhub_api.config import get_settings
from guardhub_api.db.models import RecoveryCode, User

CODES = 10
_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i


def _hash(code: str) -> str:
    normalized = "".join(ch for ch in code.lower() if ch in _ALPHABET)
    return keyed_hash(get_settings().hash_pepper.get_secret_value(), f"recovery:{normalized}")


def _new_code() -> str:
    raw = "".join(secrets.choice(_ALPHABET) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


async def generate(session: AsyncSession, user_id: uuid.UUID) -> list[str]:
    """Ten fresh codes; any older codes of this account stop working."""
    await session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))
    codes = [_new_code() for _ in range(CODES)]
    for c in codes:
        session.add(RecoveryCode(user_id=user_id, code_hash=_hash(c)))
    await session.flush()
    return codes


async def consume(session: AsyncSession, user_id: uuid.UUID, code: str) -> bool:
    """True once for a valid unused code of this account (then it is spent)."""
    row = (
        await session.execute(
            select(RecoveryCode)
            .where(RecoveryCode.user_id == user_id, RecoveryCode.code_hash == _hash(code))
            .with_for_update()
        )
    ).scalar_one_or_none()
    if row is None or row.used_at is not None:
        return False
    row.used_at = datetime.now(UTC)
    return True


async def remaining(session: AsyncSession, user_id: uuid.UUID) -> int:
    stmt = (
        select(func.count())
        .select_from(RecoveryCode)
        .where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
    )
    return int((await session.execute(stmt)).scalar_one())


async def clear(session: AsyncSession, user_id: uuid.UUID) -> None:
    await session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user_id))


async def current_code_ok(redis: Redis, user: User, code: str, secret: str) -> bool:
    """A current authenticator code of `user` (decrypted `secret`), with replay protection."""
    step = totp_matching_step(secret, code)
    replay_key = f"gh:totp:last:{user.id}"
    last = await redis.get(replay_key)
    if step is None or (last is not None and step <= int(last)):
        return False
    await redis.set(replay_key, str(step), ex=300)
    return True
