from __future__ import annotations

import asyncio
import json
import uuid

import fakeredis
import pytest
from fastapi.testclient import TestClient

from guardhub_api.ai.provider import NoopAIProvider, get_provider, status
from guardhub_api.common import ratelimit
from guardhub_api.common.errors import RateLimitedError
from guardhub_api.config import get_settings
from guardhub_api.scans import queue


@pytest.fixture
def redis() -> fakeredis.FakeAsyncRedis:
    return fakeredis.FakeAsyncRedis(decode_responses=True)


async def test_enqueue_scan_payload_matches_contract(redis: fakeredis.FakeAsyncRedis) -> None:
    scan_id = uuid.uuid4()
    await queue.enqueue_scan(
        redis, scan_id=scan_id, target="https://example.com", checks=["exposed_env"], deadline_seconds=120
    )
    [(_, fields)] = await redis.xrange(queue.JOBS_STREAM)
    payload = json.loads(fields["payload"])
    assert payload["v"] == 1 and payload["kind"] == "scan"
    assert payload["scan_id"] == str(scan_id)
    assert payload["target"] == "https://example.com"
    assert payload["checks"] == ["exposed_env"]
    assert payload["deadline_seconds"] == 120
    uuid.UUID(payload["job_id"])


async def _fake_scanner_reply(redis: fakeredis.FakeAsyncRedis, reply: dict[str, object] | None) -> None:
    for _ in range(100):
        entries = await redis.xrange(queue.JOBS_STREAM)
        if entries:
            job = json.loads(entries[-1][1]["payload"])
            assert job["kind"] == "verify" and job["token"] == "ghv_tok"
            if reply is not None:
                body = {"v": 1, "job_id": job["job_id"], **reply}
                await redis.lpush(job["reply_key"], json.dumps(body))
            return
        await asyncio.sleep(0.01)


@pytest.mark.parametrize(
    ("reply", "verified", "method", "error"),
    [
        ({"verified": True, "method": "well_known", "error": None}, True, "well_known", None),
        ({"verified": False, "method": None, "error": "not_found"}, False, None, "not_found"),
        ({"verified": True, "method": "telepathy", "error": None}, False, None, None),
    ],
)
async def test_request_verification_roundtrip(
    redis: fakeredis.FakeAsyncRedis,
    reply: dict[str, object],
    verified: bool,
    method: str | None,
    error: str | None,
) -> None:
    responder = asyncio.create_task(_fake_scanner_reply(redis, reply))
    result = await queue.request_verification(
        redis, target="https://example.com", token="ghv_tok", wait_seconds=2
    )
    await responder
    assert (result.verified, result.method, result.error) == (verified, method, error)


async def test_request_verification_times_out(redis: fakeredis.FakeAsyncRedis) -> None:
    responder = asyncio.create_task(_fake_scanner_reply(redis, None))
    result = await queue.request_verification(
        redis, target="https://example.com", token="ghv_tok", wait_seconds=1
    )
    await responder
    assert not result.verified and result.error == "timeout"


async def test_request_verification_waits_across_blpop_slices(
    redis: fakeredis.FakeAsyncRedis, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A slow scanner reply (later than one BLPOP slice) is still received, not a timeout."""
    monkeypatch.setattr(queue, "BLPOP_SLICE_SECONDS", 0.2)

    async def slow_reply() -> None:
        await asyncio.sleep(0.7)
        await _fake_scanner_reply(redis, {"verified": True, "method": "dns_txt", "error": None})

    responder = asyncio.create_task(slow_reply())
    result = await queue.request_verification(
        redis, target="https://example.com", token="ghv_tok", wait_seconds=3
    )
    await responder
    assert result.verified and result.method == "dns_txt"


async def test_rate_limit_blocks_after_limit(redis: fakeredis.FakeAsyncRedis) -> None:
    for _ in range(3):
        await ratelimit.enforce(redis, "t", "k", limit=3, window=60)
    with pytest.raises(RateLimitedError) as exc:
        await ratelimit.enforce(redis, "t", "k", limit=3, window=60)
    assert 1 <= exc.value.retry_after <= 60
    await ratelimit.enforce(redis, "t", "other-key", limit=3, window=60)


async def test_ai_seam_is_noop_without_key() -> None:
    provider = get_provider(get_settings())
    assert isinstance(provider, NoopAIProvider)
    assert provider.active is False
    assert await provider.summarize_report("report", "en") is None
    assert await provider.detect_anomalies({"error_rate": 0.9}) == []
    assert status(get_settings()).active is False


def test_csrf_header_required_for_state_changes() -> None:
    from guardhub_api.main import app

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post("/api/v1/auth/login", json={"email": "a@example.com", "password": "x"})
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "csrf_header_missing"
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"


def test_unknown_route_uses_error_envelope() -> None:
    from guardhub_api.main import app

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/api/v1/does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"
    assert client.get("/docs").status_code == 404  # interactive docs disabled
