"""Trusted-domain HTTP routes (docs/architecture.md §8.5).

Every route answers 404 to anyone who is not an admin with a full MFA session, including
signed-out visitors and admins who haven't finished 2FA, so the feature isn't discoverable.
The role is re-read from the database on every request.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from guardhub_api.admin.trusted_domains import service
from guardhub_api.admin.trusted_domains.schemas import AddTrustedDomainRequest, TrustedDomainView
from guardhub_api.auth import service as auth_service
from guardhub_api.auth.deps import OptionalSession
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common.errors import NotFoundError, UnauthenticatedError
from guardhub_api.common.redis import get_redis
from guardhub_api.scans.schemas import ScanSummary


async def trusted_domains_admin(claims: OptionalSession) -> SessionClaims:
    """Admin role (from the DB) + MFA-complete session, else 404 `not_found`."""
    if claims is None or not claims.mfa:
        raise NotFoundError("not_found", "Not found.")
    try:
        role = await auth_service.current_role(claims.user_id)
    except UnauthenticatedError as exc:
        raise NotFoundError("not_found", "Not found.") from exc
    if role != "admin":
        raise NotFoundError("not_found", "Not found.")
    return claims


TrustedDomainsAdmin = Annotated[SessionClaims, Depends(trusted_domains_admin)]

router = APIRouter(prefix="/admin/trusted-domains", tags=["admin"])


@router.get("")
async def list_domains(claims: TrustedDomainsAdmin) -> list[TrustedDomainView]:
    return await service.list_domains(claims)


@router.post("", status_code=status.HTTP_201_CREATED)
async def add_domain(body: AddTrustedDomainRequest, claims: TrustedDomainsAdmin) -> TrustedDomainView:
    return await service.add_domain(claims, body.target_url)


@router.post("/{domain_id}/verify")
async def verify_domain(domain_id: uuid.UUID, claims: TrustedDomainsAdmin) -> TrustedDomainView:
    return await service.verify_domain(get_redis(), claims, domain_id)


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_domain(domain_id: uuid.UUID, claims: TrustedDomainsAdmin) -> None:
    await service.revoke_domain(claims, domain_id)


@router.post("/{domain_id}/scan", status_code=status.HTTP_202_ACCEPTED)
async def scan_domain(domain_id: uuid.UUID, claims: TrustedDomainsAdmin) -> ScanSummary:
    return await service.scan_domain(get_redis(), claims, domain_id)
