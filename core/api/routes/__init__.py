# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Node route packages: system, config, stats, users (see each module).

The sub-routers are merged here.
"""

from __future__ import annotations

from fastapi import APIRouter

from core.api.routes.config import router as config_router
from core.api.routes.stats import router as stats_router
from core.api.routes.system import router as system_router
from core.api.routes.users import router as users_router

__all__ = ["router"]

# No prefix here: each sub-router already carries /sync, and include_router
# concatenates prefixes — one here would make every path /sync/sync.
router = APIRouter()
for sub in (system_router, config_router, stats_router, users_router):
    router.include_router(sub)
