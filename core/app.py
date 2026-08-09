import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from core.config import settings
from core.logger import logger
from core.pki_setup import init_pki
from core.routers import core_router


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        if request.url.scheme == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize PKI (idempotent — skips if CA already exists)."""
    logger.info("Starting OV-Node — initializing PKI...")
    init_pki()
    from core.service.multilogin import ensure_multilogin_setup

    ensure_multilogin_setup()
    yield
    logger.info("OV-Node shutting down.")


api = FastAPI(
    title="OV Node",
    docs_url="/doc" if settings.doc else None,
    lifespan=lifespan,
)

# Apply security headers middleware
_panel_origins = [
    origin.strip()
    for origin in os.getenv("PANEL_ORIGINS", "http://localhost:5173,http://localhost:2095").split(",")
    if origin.strip()
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
