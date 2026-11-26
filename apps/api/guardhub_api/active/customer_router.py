"""Customer active-test routes (Phase 5B), the signed-in customer's own sites only. Built and off:
see active/customer_scan.py for every lock, the founder's go-live gate first."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from guardhub_api.active import customer_scan
from guardhub_api.auth.deps import FullSession
from guardhub_api.common.redis import get_redis

router = APIRouter(prefix="/projects/{project_id}/active", tags=["active"])


@router.get("")
async def readiness(project_id: uuid.UUID, claims: FullSession) -> customer_scan.Readiness:
    return await customer_scan.readiness(claims, get_redis(), project_id)


@router.post("/scans", status_code=status.HTTP_202_ACCEPTED)
async def start(
    project_id: uuid.UUID, body: customer_scan.StartRequest, claims: FullSession
) -> customer_scan.Started:
    return await customer_scan.start(claims, get_redis(), project_id, body)


@router.post("/scans/{scan_id}/stop", status_code=status.HTTP_204_NO_CONTENT)
async def stop(project_id: uuid.UUID, scan_id: uuid.UUID, claims: FullSession) -> None:
    await customer_scan.stop(claims, get_redis(), project_id, scan_id)
