from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from core.config import settings
from core.logger import logger
from core.routers import core_router
from core.pki_setup import init_pki
from core.security import setup_security_headers


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
api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

api.include_router(core_router)
