"""Auth HTTP routes (docs/architecture.md §4.3). Thin: HTTP ↔ service only."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response, status
from redis.asyncio import Redis

from guardhub_api.auth import service, sessions
from guardhub_api.auth.deps import AnySession, FullSession, clear_session_cookie, set_session_cookie
from guardhub_api.auth.schemas import (
    LoginRequest,
    MfaState,
    RecoveryCodeRequest,
    RecoveryCodes,
    RecoveryStatus,
    RegisterRequest,
    RegisterResponse,
    SessionResponse,
    TotpSetupResponse,
    TotpVerifyRequest,
    UpdateMeRequest,
    UserView,
)
from guardhub_api.auth.security import SessionClaims
from guardhub_api.common.crypto import keyed_hash
from guardhub_api.common.redis import get_redis
from guardhub_api.common.request_meta import client_ip
from guardhub_api.config import get_settings
from guardhub_api.db.models import User

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(body: RegisterRequest, request: Request, response: Response) -> RegisterResponse:
    user = await service.register(
        get_redis(), email=str(body.email), password=body.password, locale=body.locale, ip=client_ip(request)
    )
    set_session_cookie(response, service.pre_mfa_session(user))
    return RegisterResponse(user=service.user_view(user, mfa_complete=False), mfa="setup_required")


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response) -> MfaState:
    user = await service.login(
        get_redis(), email=str(body.email), password=body.password, ip=client_ip(request)
    )
    set_session_cookie(response, service.pre_mfa_session(user))
    return MfaState(mfa="required" if user.totp_enabled else "setup_required")


@router.post("/2fa/setup")
async def totp_setup(claims: AnySession) -> TotpSetupResponse:
    secret, uri = await service.setup_totp(claims)
    return TotpSetupResponse(secret=secret, otpauth_uri=uri)


@router.post("/2fa/verify")
async def totp_verify(
    body: TotpVerifyRequest, claims: AnySession, request: Request, response: Response
) -> SessionResponse:
    redis = get_redis()
    user, codes = await service.verify_totp(redis, claims, body.code)
    await _full_session(redis, claims, user, request, response)
    return SessionResponse(user=service.user_view(user, mfa_complete=True), recovery_codes=codes)


async def _full_session(
    redis: Redis, claims: SessionClaims, user: User, request: Request, response: Response
) -> None:
    await service.revoke(redis, claims)  # rotate: the pre-MFA token dies, a fresh full token is issued
    fresh = service.full_session(user)
    set_session_cookie(response, fresh)
    await sessions.record(  # the admin can see and end it (Prompt 2 section 5)
        redis,
        fresh,
        ip_hash=keyed_hash(get_settings().hash_pepper.get_secret_value(), client_ip(request)),
        user_agent=request.headers.get("user-agent", ""),
    )


@router.post("/2fa/recover")
async def totp_recover(
    body: RecoveryCodeRequest, claims: AnySession, request: Request, response: Response
) -> SessionResponse:
    """Finish sign-in with a single-use recovery code instead of the authenticator code."""
    redis = get_redis()
    user = await service.recover(redis, claims, body.code)
    await _full_session(redis, claims, user, request, response)
    return SessionResponse(user=service.user_view(user, mfa_complete=True))


@router.get("/2fa/recovery-codes")
async def recovery_status(claims: FullSession) -> RecoveryStatus:
    return RecoveryStatus(remaining=await service.recovery_status(claims))


@router.post("/2fa/recovery-codes")
async def regenerate_recovery_codes(body: TotpVerifyRequest, claims: FullSession) -> RecoveryCodes:
    return RecoveryCodes(codes=await service.regenerate_recovery_codes(get_redis(), claims, body.code))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(claims: AnySession, response: Response) -> None:
    await service.logout(get_redis(), claims)
    await sessions.forget(get_redis(), claims.user_id, claims.jti)
    clear_session_cookie(response)


@router.get("/me")
async def me(claims: AnySession) -> UserView:
    user = await service.get_user(claims)
    return service.user_view(user, mfa_complete=claims.mfa)


@router.patch("/me")
async def update_me(body: UpdateMeRequest, claims: AnySession) -> UserView:
    user = await service.update_locale(claims, body.locale)
    return service.user_view(user, mfa_complete=claims.mfa)
