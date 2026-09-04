# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

import os
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from core.api.routes import router as core_router
from core.config import settings
from core.logger import logger
from core.openvpn.pki import init_pki


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # API-only service: no inline scripts/styles needed anywhere.
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; form-action 'none'"
        )
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize PKI + OpenVPN config (idempotent).

    Degraded start: PKI failures must not kill the API — the panel needs
    /sync/status diagnostics precisely when the node is broken.
    """
    logger.info("Starting OV-Node — initializing PKI...")
    app.state.degraded = None
    try:
        init_pki()
    except Exception as e:
        app.state.degraded = str(e)
        logger.error("PKI init failed — starting degraded API: %s", e, exc_info=e)
    try:
        from core.openvpn.multilogin import ensure_multilogin_setup

        ensure_multilogin_setup()
    except Exception as e:
        logger.error("multilogin setup failed: %s", e, exc_info=e)
        if app.state.degraded is None:
            app.state.degraded = str(e)

    from core.openvpn.control import openvpn_is_running

    if openvpn_is_running():
        logger.info("OpenVPN server is running.")
    else:
        logger.warning(
            "OpenVPN server is not running — start it with: "
            "systemctl restart openvpn-server@server (or check /dev/net/tun)"
        )
    yield
    logger.info("OV-Node shutting down.")


api = FastAPI(
    title="OV Node",
    docs_url="/doc" if settings.doc else None,
    lifespan=lifespan,
)

# Apply security headers middleware
_panel_origins = [
    origin.strip() for origin in os.getenv("PANEL_ORIGINS", "").split(",") if origin.strip()
]
api.add_middleware(
    CORSMiddleware,
    allow_origins=_panel_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["key", "content-type", "authorization", "x-requested-with"],
)
api.add_middleware(SecurityHeadersMiddleware)

api.include_router(core_router)


# ── error handling ───────────────────────────────────────────────────
# The panel accepts a call only when it gets HTTP 200 + {"success": true},
# so every failure — expected or not — must come back in the same envelope.
# Unhandled exceptions additionally get a short reference id that links the
# response to the full traceback in the logs (and GET /sync/logs).


@api.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    """Contract-shaped body for expected HTTP errors (401/404/422/429...)."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"success": False, "msg": str(exc.detail), "data": None},
        headers=getattr(exc, "headers", None),
    )


@api.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Malformed panel payloads: log the offender, answer in contract shape."""
    problems = "; ".join(
        f"{'.'.join(str(p) for p in e.get('loc', []))}: {e.get('msg', '')}" for e in exc.errors()
    )
    logger.warning("Invalid request %s %s — %s", request.method, request.url.path, problems)
    return JSONResponse(
        status_code=422,
        content={"success": False, "msg": f"Invalid request: {problems}", "data": None},
    )


@api.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Last-resort handler: never leak a traceback, always leave a trail.

    The short ``ref`` ties this response to the full stack trace in the
    node log — searchable via ``GET /sync/logs`` or ``grep ref data/app.log``.
    """
    ref = uuid.uuid4().hex[:8]
    logger.error(
        "Unhandled error ref=%s on %s %s: %s",
        ref,
        request.method,
        request.url.path,
        exc,
        exc_info=exc,
    )
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "msg": f"Internal node error (ref={ref}, see node logs)",
            "data": None,
        },
    )
