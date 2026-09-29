# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Node route packages: system, config, stats, users (see each module).

``from core.api.routes import router`` keeps working: the sub-routers are
merged here. Shared helpers imported by tests stay re-exported.
"""

from __future__ import annotations

from fastapi import APIRouter

from core.api.routes.config import router as config_router
from core.api.routes.stats import router as stats_router
from core.api.routes.system import _openssl_enddate, _resolve_identity
from core.api.routes.system import router as system_router
from core.api.routes.users import router as users_router

__all__ = ["router", "_resolve_identity", "_openssl_enddate"]

# Aggregator WITHOUT its own prefix: each sub-router already carries the
# /sync prefix (they were split from a single router with prefix="/sync"),
# and include_router concatenates prefixes — an aggregator prefix would
# double it to /sync/sync.
router = APIRouter()
for sub in (system_router, config_router, stats_router, users_router):
    router.include_router(sub)
