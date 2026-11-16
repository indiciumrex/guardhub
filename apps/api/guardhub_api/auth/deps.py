"""FastAPI dependencies for authentication and authorisation, plus session-cookie helpers.

- `any_session`: any valid, unrevoked session (including pre-MFA). Only used to finish 2FA.
- `full_session`: MFA-complete session; required for account/projects/scans (§9.1).
- `admin_session`: MFA-complete AND role=admin, with the role re-read from the DB on every
  request so a demoted admin loses access immediately.
"""

from __future__ import annotations

import time
from typing import Annotated

from fastapi import Depends, Request, Response

from guardhub_api.auth import service
from guardhub_api.auth.security import SessionClaims, decode_session, encode_session
from guardhub_api.common.errors import ForbiddenError, NotFoundError, UnauthenticatedError
from guardhub_api.common.redis import get_redis
from guardhub_api.config import get_settings

COOKIE_NAME = "gh_session"


def set_session_cookie(response: Response, claims: SessionClaims) -> None:
    settings = get_settings()
    response.set_cookie(
        COOKIE_NAME,
        encode_session(settings.jwt_secret.get_secret_value(), claims),
        max_age=max(1, claims.exp - int(time.time())),
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        COOKIE_NAME, path="/", secure=settings.cookie_secure, httponly=True, samesite="strict"
    )


async def optional_session(request: Request) -> SessionClaims | None:
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    claims = decode_session(get_settings().jwt_secret.get_secret_value(), token)
    if claims is None or await service.is_revoked(get_redis(), claims.jti):
        return None
    return claims


async def any_session(claims: Annotated[SessionClaims | None, Depends(optional_session)]) -> SessionClaims:
    if claims is None:
        raise UnauthenticatedError("not_authenticated", "Please sign in.")
    return claims


async def full_session(claims: Annotated[SessionClaims, Depends(any_session)]) -> SessionClaims:
    if not claims.mfa:
        raise ForbiddenError("mfa_required", "Complete two-factor authentication first.")
    return claims


async def admin_session(claims: Annotated[SessionClaims, Depends(full_session)]) -> SessionClaims:
    if await service.current_role(claims.user_id) != "admin":
        # 404, not 403: don't reveal that the admin surface exists.
        raise NotFoundError("not_found", "Not found.")
    return claims


AnySession = Annotated[SessionClaims, Depends(any_session)]
FullSession = Annotated[SessionClaims, Depends(full_session)]
AdminSession = Annotated[SessionClaims, Depends(admin_session)]
OptionalSession = Annotated[SessionClaims | None, Depends(optional_session)]
