"""FastAPI application entrypoint: wires routers, the error envelope, CSRF guard and headers.

Run with `uvicorn guardhub_api.main:app`. All routes live under /api/v1 and are reached through
the web app's same-origin rewrite. Interactive docs are disabled (a smaller public surface).
"""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from guardhub_api.admin.router import router as admin_router
from guardhub_api.admin.trusted_domains.router import router as trusted_domains_router
from guardhub_api.alerts.router import router as alerts_router
from guardhub_api.auth.router import router as auth_router
from guardhub_api.common.errors import install_error_handlers
from guardhub_api.common.logging import configure_logging
from guardhub_api.common.observability import init_observability
from guardhub_api.common.redis import close_redis
from guardhub_api.config import get_settings
from guardhub_api.db.session import dispose_engine
from guardhub_api.github.router import router as github_router
from guardhub_api.health.router import router as health_router
from guardhub_api.jobs.client import close_arq
from guardhub_api.projects.router import router as projects_router
from guardhub_api.scans.router import public_router
from guardhub_api.scans.router import router as scans_router

log = logging.getLogger("guardhub.http")

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
CSRF_HEADER = "x-guardhub-csrf"
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    configure_logging(get_settings().log_level)
    yield
    await close_arq()
    await close_redis()
    await dispose_engine()


def create_app() -> FastAPI:
    get_settings()  # fail fast on missing or weak configuration
    init_observability("api")  # no-op unless SENTRY_DSN is set
    app = FastAPI(
        title="GuardHub API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    install_error_handlers(app)

    @app.middleware("http")
    async def guard(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        start = time.perf_counter()
        # CSRF: a cross-site form can't set custom headers, and a cross-site fetch with one would
        # need a CORS preflight that this API never approves.
        if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != "1":
            response: Response = JSONResponse(
                {"error": {"code": "csrf_header_missing", "message": "Missing X-GuardHub-CSRF header."}},
                status_code=403,
            )
        else:
            response = await call_next(request)
        response.headers.update(SECURITY_HEADERS)
        response.headers["X-Request-Id"] = request_id[:64]
        log.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": int((time.perf_counter() - start) * 1000),
                "request_id": request_id[:64],
            },
        )
        return response

    api = APIRouter(prefix="/api/v1")
    for r in (
        health_router,
        auth_router,
        public_router,
        projects_router,
        scans_router,
        admin_router,
        trusted_domains_router,
        alerts_router,
        github_router,
    ):
        api.include_router(r)
    app.include_router(api)
    return app


app = create_app()
