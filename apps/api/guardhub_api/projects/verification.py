"""Ownership verification (§9.2, ADR-0001), shared by projects and anonymous challenges.

Builds the instructions shown to users and asks the scanner (the only component that talks
to targets) to check the proof. Accepted proofs: a well-known file, a meta tag, or a DNS TXT record.
"""

from __future__ import annotations

from pydantic import BaseModel
from redis.asyncio import Redis
from redis.exceptions import RedisError

from guardhub_api.common.crypto import random_token
from guardhub_api.common.errors import ServiceUnavailableError, UnprocessableError
from guardhub_api.common.urls import origin_host
from guardhub_api.config import get_settings
from guardhub_api.scans import queue

WELL_KNOWN_PATH = "/.well-known/guardhub-verify.txt"


class VerificationInstructions(BaseModel):
    token: str
    well_known_url: str
    meta_tag: str
    dns_name: str
    dns_value: str


def new_token() -> str:
    return random_token("ghv")


def instructions(origin: str, token: str) -> VerificationInstructions:
    return VerificationInstructions(
        token=token,
        well_known_url=origin + WELL_KNOWN_PATH,
        meta_tag=f'<meta name="guardhub-verification" content="{token}">',
        dns_name=f"_guardhub.{origin_host(origin)}",
        dns_value=f"guardhub-verify={token}",
    )


async def prove_ownership(redis: Redis, *, origin: str, token: str) -> str:
    """Return the method that proved ownership, or raise 422 `ownership_not_verified`."""
    try:
        result = await queue.request_verification(
            redis, target=origin, token=token, wait_seconds=get_settings().verify_timeout_seconds
        )
    except RedisError as exc:
        raise ServiceUnavailableError(
            "queue_unavailable", "Verification is temporarily unavailable."
        ) from exc
    if not result.verified or result.method is None:
        raise UnprocessableError(
            "ownership_not_verified",
            "We could not find your verification token on the site.",
            {"reason": result.error or "not_found"},
        )
    return result.method
