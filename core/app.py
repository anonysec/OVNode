from fastapi import FastAPI

from core.routers import core_router
from core.config import settings
from core.service.multilogin import ensure_multilogin_setup

api = FastAPI(title="OV Node", docs_url="/doc" if settings.doc else None)

api.include_router(core_router)


@api.on_event("startup")
async def _setup_multilogin() -> None:
    """Ensure the per-config connection-limit enforcement is in place.
    This is critical for multi-login to actually work after restarts or node edits.
    """
    from core.service.multilogin import ensure_multilogin_setup
    ensure_multilogin_setup()
