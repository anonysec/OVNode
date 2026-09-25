# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""OVNode sync API — the node side of the OVManager ⇄ OVNode contract.

Each endpoint corresponds 1:1 to a method of OVManager's ``NodeRequests``
client (backend/node/requests.py):

    GET    /sync/health                      (Docker healthcheck — no auth)
    GET    /sync/status                      check_node / get_node_info
    GET    /sync/usage                       get_usage
    GET    /sync/sessions                    get_sessions
    GET    /sync/config                      read_config (drift detect)
    POST   /sync/config                      update_config
    POST   /sync/restart                     restart_vpn
    POST   /sync/user                        create_user
    PUT    /sync/user                        change_user_status
    PUT    /sync/user/limit                  set_user_limit
    DELETE /sync/user/{uid}                  delete_user
    POST   /sync/user/{uid}/disconnect       disconnect_user
    POST   /sync/user/{uid}/reset-usage      reset_user_usage
    GET    /sync/download/ovpn/{uid}         download_ovpn_client / _bytes
    POST   /sync/update                      trigger_update

The panel treats a call as successful ONLY when the response is HTTP 200
with ``{"success": true}`` — so handlers report business failures inside the
envelope instead of raising, except where the panel explicitly checks the
HTTP status (ovpn download must be a raw 200 body starting with "client").

Authentication: the panel sends the node API key in the ``key`` header.
"""

from fastapi import APIRouter, Depends

from core.api.auth import check_api_key
from core.api.schemas import ResponseModel
from core.openvpn.sessions import user_diagnostics
from core.openvpn.users import (
    get_users_usage,
)

router = APIRouter(prefix="/sync", tags=["node_sync"])


@router.get("/usage", response_model=ResponseModel)
async def get_all_user_usage(api_key: str = Depends(check_api_key)):
    """Traffic counters — consumed by get_usage() (traffic sync + mlogin).

    ``data`` always carries {"users": {...}, "sessions": {...}} so the
    panel's per-session delta path and global-mlogin live-session scan both
    work; empty dicts simply mean nobody is connected.
    """
    usages = get_users_usage()
    if usages.get("users"):
        return ResponseModel(success=True, msg="Latest user usage received", data=usages)
    return ResponseModel(success=True, msg="No user is using it.", data=usages)


@router.get("/sessions", response_model=ResponseModel)
async def get_session_diagnostics(
    common_name: str | None = None,
    hours: int = 8,
    api_key: str = Depends(check_api_key),
):
    """Live sessions, stale markers and recent max-login auth errors.

    Consumed by get_sessions() for node metrics, stale-session cleanup,
    per-user diagnostics and the frontend NodeDrawer sessions tab.
    """
    return ResponseModel(
        success=True,
        msg="Session diagnostics retrieved successfully",
        data=user_diagnostics(common_name=common_name, hours=hours),
    )
