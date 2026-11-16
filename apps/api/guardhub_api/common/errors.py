"""Single error hierarchy for the API (§7.1).

Services raise these domain errors; `install_error_handlers` is the ONLY place they're translated
into HTTP responses with the envelope `{"error": {"code", "message", "details"?}}`.
Unexpected exceptions become a generic 500 with no internal details leaked.
"""

from __future__ import annotations

import logging
from typing import ClassVar

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

log = logging.getLogger("guardhub.errors")


class GuardHubError(Exception):
    """Base domain error. Subclasses fix the HTTP status; `code` is a stable snake_case id."""

    status_code: ClassVar[int] = 400

    def __init__(self, code: str, message: str, details: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details


class BadRequestError(GuardHubError):
    status_code = 400


class UnauthenticatedError(GuardHubError):
    status_code = 401


class ForbiddenError(GuardHubError):
    status_code = 403


class NotFoundError(GuardHubError):
    status_code = 404


class ConflictError(GuardHubError):
    status_code = 409


class UnprocessableError(GuardHubError):
    status_code = 422


class RateLimitedError(GuardHubError):
    status_code = 429

    def __init__(self, retry_after: int) -> None:
        super().__init__("rate_limited", "Too many requests, slow down.", {"retry_after": str(retry_after)})
        self.retry_after = retry_after


class ServiceUnavailableError(GuardHubError):
    status_code = 503


def _envelope(code: str, message: str, details: dict[str, str] | None = None) -> dict[str, object]:
    body: dict[str, object] = {"code": code, "message": message}
    if details:
        body["details"] = details
    return {"error": body}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(GuardHubError)
    async def _domain(_: Request, exc: GuardHubError) -> JSONResponse:
        headers = {"Retry-After": str(exc.retry_after)} if isinstance(exc, RateLimitedError) else None
        return JSONResponse(
            _envelope(exc.code, exc.message, exc.details), status_code=exc.status_code, headers=headers
        )

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        fields = {
            ".".join(str(p) for p in err.get("loc", ()) if p != "body"): str(err.get("type", "invalid"))
            for err in exc.errors()
        }
        return JSONResponse(_envelope("validation_error", "Invalid request.", fields), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return JSONResponse(_envelope(code, str(exc.detail)), status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled_error", extra={"path": request.url.path})
        return JSONResponse(_envelope("internal_error", "Something went wrong."), status_code=500)
