"""Integration fixtures: a real PostgreSQL (migrated, app role under RLS) and real Redis.

Enable with:
  GUARDHUB_TEST_DATABASE_URL=postgresql+asyncpg://guardhub_app:<pw>@127.0.0.1:55432/guardhub_test
  GUARDHUB_TEST_REDIS_URL=redis://127.0.0.1:56379/0
A fake scanner speaks the exact Redis wire protocol (docs/architecture.md §2), so the API is
exercised end-to-end except for the network probing (covered by the Go tests).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime

import httpx
import pyotp
import pytest
from redis.asyncio import Redis

if not os.environ.get("GUARDHUB_TEST_DATABASE_URL"):
    pytest.skip("integration tests need GUARDHUB_TEST_DATABASE_URL", allow_module_level=True)

from guardhub_api.common.redis import get_redis
from guardhub_api.main import app
from guardhub_api.scans.queue import EVENTS_STREAM, JOBS_STREAM


@dataclass
class FakeScanner:
    redis: Redis
    verify_ok: bool = True
    findings: list[dict[str, object]] = field(default_factory=list)
    fail_scan: str | None = None
    failed_checks: set[str] = field(default_factory=set)  # checks reported as failed (timeout)
    last_id: str = "$"
    scan_jobs: list[dict[str, object]] = field(default_factory=list)

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            res = await self.redis.xread({JOBS_STREAM: self.last_id}, count=10, block=50)
            for _stream, messages in res or []:
                for msg_id, fields in messages:
                    self.last_id = msg_id
                    await self.handle(json.loads(fields["payload"]))

    async def handle(self, job: dict[str, object]) -> None:
        now = datetime.now(UTC).isoformat()
        if job["kind"] == "verify":
            reply = {"v": 1, "job_id": job["job_id"], "verified": self.verify_ok,
                     "method": "well_known" if self.verify_ok else None,
                     "error": None if self.verify_ok else "not_found"}  # fmt: skip
            await self.redis.lpush(str(job["reply_key"]), json.dumps(reply))
            return
        self.scan_jobs.append(job)
        sid = job["scan_id"]
        await self.redis.xadd(
            EVENTS_STREAM,
            {"payload": json.dumps({"v": 1, "type": "scan.started", "scan_id": sid, "at": now})},
        )
        if self.fail_scan:
            event = {"v": 1, "type": "scan.failed", "scan_id": sid, "at": now, "error": self.fail_scan}
        else:
            results = [{"check_id": c, "status": "failed" if c in self.failed_checks else "done",
                        "error": "timeout" if c in self.failed_checks else None} for c in job["checks"]]  # type: ignore[union-attr]  # fmt: skip
            findings = [f for f in self.findings if f["check_id"] not in self.failed_checks]
            event = {"v": 1, "type": "scan.completed", "scan_id": sid, "at": now, "findings": findings,
                     "check_results": results}  # fmt: skip
        await self.redis.xadd(EVENTS_STREAM, {"payload": json.dumps(event)})


def raw_finding(
    check_id: str, key: str, location: str, params: dict[str, str] | None = None
) -> dict[str, object]:
    return {
        "check_id": check_id,
        "finding_key": key,
        "severity": "info",
        "params": params or {},
        "evidence": {"kind": "http_response", "location": location, "redacted_payload": "API_KEY=****wxyz"},
        "fingerprint": hashlib.sha256(f"{check_id}|{key}|{location}".encode()).hexdigest(),
    }


@pytest.fixture
async def redis() -> AsyncIterator[Redis]:
    client = get_redis()
    await client.flushdb()
    yield client


@pytest.fixture
async def scanner(redis: Redis) -> AsyncIterator[FakeScanner]:
    fake = FakeScanner(redis)
    stop = asyncio.Event()
    task = asyncio.create_task(fake.run(stop))
    await asyncio.sleep(0.05)
    yield fake
    stop.set()
    await task


def new_client(ip: str = "198.51.100.7") -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=(ip, 40000))
    return httpx.AsyncClient(transport=transport, base_url="http://test", headers={"X-GuardHub-CSRF": "1"})


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    async with new_client() as c:
        yield c


async def signed_in(client: httpx.AsyncClient, email: str | None = None) -> tuple[str, str]:
    """Register + enable TOTP; returns (email, totp secret). The client then holds a full session."""
    email = email or f"user-{uuid.uuid4().hex[:10]}@example.com"
    r = await client.post(
        "/api/v1/auth/register", json={"email": email, "password": "a-Strong-passphrase-42", "locale": "tr"}
    )
    assert r.status_code == 201, r.text
    r = await client.post("/api/v1/auth/2fa/setup")
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    r = await client.post("/api/v1/auth/2fa/verify", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    return email, secret


def next_code(secret: str) -> str:
    """A valid code for the next time step (the current one was consumed: replay protection)."""
    return pyotp.TOTP(secret).at(time.time() + 30)
