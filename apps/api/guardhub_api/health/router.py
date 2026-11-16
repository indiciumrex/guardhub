"""Public health and check-catalog routes (docs/architecture.md §4.1)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Query, Request, Response
from pydantic import BaseModel

from guardhub_api.common.redis import get_redis
from guardhub_api.common.request_meta import resolve_locale
from guardhub_api.db.session import DbContext, db_session
from guardhub_api.findings.catalog import check_description, check_name
from guardhub_api.findings.contract_gen import CHECK_IDS
from guardhub_api.health.service import LiveHealth, live_status
from guardhub_api.modules.registry import enabled_check_ids

router = APIRouter(tags=["health"])


class CheckInfo(BaseModel):
    id: str
    name: str
    description: str
    enabled: bool


@router.get("/health")
async def health(response: Response) -> LiveHealth:
    result = await live_status(get_redis())
    if result.status == "down":
        response.status_code = 503
    return result


@router.get("/checks")
async def checks(
    request: Request, locale: Annotated[str | None, Query(max_length=10)] = None
) -> list[CheckInfo]:
    resolved = resolve_locale(locale, None, request.headers.get("accept-language"))
    async with db_session(DbContext(role="anon")) as session:
        enabled = set(await enabled_check_ids(session))
    return [
        CheckInfo(
            id=cid,
            name=check_name(cid, resolved),
            description=check_description(cid, resolved),
            enabled=cid in enabled,
        )
        for cid in CHECK_IDS
    ]
