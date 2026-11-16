"""Scan HTTP routes: the anonymous free-scan flow (§4.2) and authenticated scan reports (§4.4)."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Header, Query, Request, status

from guardhub_api.auth import service as auth_service
from guardhub_api.auth.deps import FullSession
from guardhub_api.common.redis import get_redis
from guardhub_api.common.request_meta import client_ip, resolve_locale
from guardhub_api.scans import public
from guardhub_api.scans import service as scan_service
from guardhub_api.scans.schemas import ChallengeRequest, ScanView

public_router = APIRouter(prefix="/public", tags=["public"])
router = APIRouter(prefix="/scans", tags=["scans"])

LocaleQuery = Annotated[str | None, Query(max_length=10)]


@public_router.post("/challenges", status_code=status.HTTP_201_CREATED)
async def create_challenge(body: ChallengeRequest, request: Request) -> public.ChallengeView:
    return await public.create_challenge(get_redis(), target_url=body.target_url, ip=client_ip(request))


@public_router.post("/challenges/{challenge_id}/scan", status_code=status.HTTP_202_ACCEPTED)
async def start_scan(challenge_id: uuid.UUID, request: Request) -> public.StartedScan:
    return await public.verify_and_scan(get_redis(), challenge_id=challenge_id, ip=client_ip(request))


@public_router.get("/scans/{scan_id}")
async def get_public_scan(
    scan_id: uuid.UUID,
    request: Request,
    x_scan_token: Annotated[str, Header(min_length=8, max_length=128)],
    locale: LocaleQuery = None,
) -> ScanView:
    return await public.get_public_scan(
        get_redis(),
        scan_id=scan_id,
        access_token=x_scan_token,
        locale=resolve_locale(locale, None, request.headers.get("accept-language")),
    )


@router.get("/{scan_id}")
async def get_scan(
    scan_id: uuid.UUID, request: Request, claims: FullSession, locale: LocaleQuery = None
) -> ScanView:
    user = await auth_service.get_user(claims)
    resolved = resolve_locale(locale, user.locale, request.headers.get("accept-language"))
    return await scan_service.owned_view(get_redis(), claims, scan_id, resolved)
