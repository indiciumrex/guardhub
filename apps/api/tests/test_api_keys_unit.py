"""Integration keys and traffic (Prompt 2 §4): a key is always the user role; p95 from buckets."""

from __future__ import annotations

import uuid

import pytest

from guardhub_api.common.errors import ForbiddenError
from guardhub_api.integrations import traffic
from guardhub_api.integrations.keys import KeyPrincipal


def test_a_key_principal_is_always_the_user_role() -> None:
    p = KeyPrincipal(key_id=uuid.uuid4(), owner_id=uuid.uuid4(), scopes=frozenset({"scans:read"}))
    assert p.ctx.role == "user" and p.ctx.user_id == p.owner_id
    assert p.actor.startswith("apikey:")
    p.require("scans:read")
    with pytest.raises(ForbiddenError):
        p.require("scans:trigger")


class _Redis:
    def __init__(self, data: dict[str, dict[bytes, bytes]]) -> None:
        self.data = data

    async def hgetall(self, key: str) -> dict[bytes, bytes]:
        return self.data.get(key, {})


async def test_summary_and_p95() -> None:
    now = 1_800_000_000.0
    h = int(now // 3600)
    name = b"GET /api/v1/scans/{scan_id}"
    data = {
        f"{traffic.PREFIX}{h}": {
            name + b"|n": b"20", name + b"|ms": b"2000", name + b"|b50": b"10", name + b"|b100": b"8",
            name + b"|b1000": b"2", name + b"|4xx": b"3", name + b"|5xx": b"1", name + b"|429": b"2",
        },
        f"{traffic.PREFIX}{h - 1}": {name + b"|n": b"0"},
    }  # fmt: skip
    [row] = await traffic.summary(_Redis(data), 2, now)  # type: ignore[arg-type]
    assert row.endpoint == "GET /api/v1/scans/{scan_id}"
    assert (row.requests, row.client_errors, row.server_errors, row.rate_limited) == (20, 3, 1, 2)
    assert row.avg_ms == 100 and row.error_rate == 0.05
    assert row.p95_ms == 1000  # 18 of 20 within 100 ms, the 19th falls in the 1 s bucket


def test_latency_buckets() -> None:
    assert traffic._bucket(10) == "50" and traffic._bucket(50) == "50" and traffic._bucket(51) == "100"
    assert traffic._bucket(99999) == "inf"


async def test_route_template_keeps_router_prefixes_and_drops_ids() -> None:
    import httpx
    from fastapi import APIRouter, FastAPI, Request

    app = FastAPI()
    seen: list[str] = []

    @app.middleware("http")
    async def mw(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        seen.append(traffic.route_template(request.scope))
        return response

    inner = APIRouter(prefix="/integrations")

    @inner.get("/scans/{scan_id}")
    async def scan(scan_id: str) -> dict[str, str]:
        return {"id": scan_id}

    api = APIRouter(prefix="/api/v1")
    api.include_router(inner)
    app.include_router(api)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        await c.get("/api/v1/integrations/scans/11111111-aaaa")
        await c.get("/api/v1/nowhere/123")
    assert seen == ["/api/v1/integrations/scans/{scan_id}", "unmatched"]
