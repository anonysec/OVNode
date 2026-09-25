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

import os

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse

from core.api.auth import check_api_key, check_api_key_heavy
from core.api.routes.system import _resolve_identity
from core.api.schemas import BulkUserLimits, ResponseModel, User, UserLimit
from core.openvpn.sessions import disconnect_user
from core.openvpn.users import (
    change_user_status as change_user_status_on_server,
)
from core.openvpn.users import (
    cn_from_uid,
    create_user_on_server,
    delete_user_on_server,
    download_ovpn_file,
    set_user_limit,
)
from core.validation import DeleteResult, validate_user_id

router = APIRouter(prefix="/sync", tags=["node_sync"])


@router.post("/user/{uid}/disconnect", response_model=ResponseModel)
async def disconnect_user_sessions(
    uid: str, only_stale: bool = False, api_key: str = Depends(check_api_key)
):
    """Best-effort disconnect for a user; also clears stale active markers.

    The panel passes either the numeric user id or a raw CN here
    (clean_stale_sessions_all_nodes() forwards marker CNs verbatim).

    ``only_stale=True`` never kills live sessions — it only removes dead
    markers, so it is safe for users that also hold a healthy session.
    """
    safe_id = validate_user_id(uid)
    if safe_id is None:
        # Business failure inside the envelope (not 400): the panel treats
        # any non-200 as a transport error and retries/logs loudly.
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
    cn = cn_from_uid(safe_id)
    return ResponseModel(
        success=True,
        msg="Disconnect command processed",
        data=disconnect_user(cn, only_stale=only_stale),
    )


@router.post("/user/{uid}/reset-usage", response_model=ResponseModel)
async def reset_user_usage(uid: str, api_key: str = Depends(check_api_key)):
    """Zero a user's banked traffic counters (panel reset-usage flow).

    Complements delete (which also clears): lets the panel restart counting
    without revoking the certificate.
    """
    from core.openvpn import store

    safe_id = validate_user_id(uid)
    if safe_id is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
    store.reset_usage(cn_from_uid(safe_id))
    return ResponseModel(success=True, msg="Usage counters reset", data={"id": safe_id})


@router.post("/users", response_model=ResponseModel)
async def bulk_user_limits(payload: BulkUserLimits, api_key: str = Depends(check_api_key)):
    """Apply max-login limits for many users in one call (POST /sync/users).

    The panel's limit sweep used to fan out one PUT /sync/user/limit per
    user per node — N×M HTTPS requests every 30 minutes. This endpoint
    takes the whole batch (capped), validates each id, and applies the
    limits in a single threadpool hop. Per-item failures are reported in
    ``data.failed`` instead of failing the whole call.
    """
    results = []
    failed = []

    def apply_all():
        for item in payload.users:
            safe_id = validate_user_id(item.id)
            if safe_id is None:
                failed.append({"id": item.id, "msg": "Invalid user id (must be UUID or simple id)"})
                continue
            if set_user_limit(safe_id, int(item.max_logins or 0)):
                results.append(safe_id)
            else:
                failed.append({"id": item.id, "msg": "Failed to update user login limit"})

    await run_in_threadpool(apply_all)
    return ResponseModel(
        success=True,
        msg=f"{len(results)} limit(s) applied, {len(failed)} failed",
        data={"applied": len(results), "failed": failed},
    )


@router.post("/user", response_model=ResponseModel)
async def create_user(user: User, api_key: str = Depends(check_api_key_heavy)):
    """Create a client certificate + .ovpn (create_user()).

    ``id`` is optional — NodeRequests only includes it when the panel knows
    the numeric user id. Without it the normalized name is the identity.
    """
    uid = _resolve_identity(user.id, user.name)
    if uid is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
    max_logins = user.max_logins if user.max_logins is not None else 1
    # easyrsa can fork for up to 120s — never run it on the event loop.
    success = await run_in_threadpool(create_user_on_server, uid, user.name or "", max_logins)
    if success:
        return ResponseModel(
            success=True,
            msg="User created successfully",
            data={"id": uid, "name": user.name},
        )
    return ResponseModel(success=False, msg="Failed to create user")


@router.delete("/user/{uid}", response_model=ResponseModel)
async def delete_user(uid: str, api_key: str = Depends(check_api_key_heavy)):
    safe_id = validate_user_id(uid)
    if safe_id is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
    # revoke + gen-crl can fork easyrsa for ~240s — off the event loop.
    result = await run_in_threadpool(delete_user_on_server, safe_id)
    if result == DeleteResult.OK:
        return ResponseModel(
            success=True,
            msg="User deleted successfully",
            data={"id": safe_id},
        )
    if result == DeleteResult.NOT_FOUND:
        # Treat NOT_FOUND as success: the cert is already gone from this node.
        # The panel's delete_user_on_all_nodes() requires all() == True, so
        # returning success here allows panel-side cleanup to proceed even when
        # the cert was already manually removed from the node.
        return ResponseModel(success=True, msg="User not found on node (already deleted)")
    return ResponseModel(success=False, msg="Failed to delete user")


@router.put("/user", response_model=ResponseModel)
async def change_user_status(user: User, api_key: str = Depends(check_api_key)):
    """Activate/deactivate a client (change_user_status())."""
    uid = _resolve_identity(user.id, user.name)
    if uid is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
    # Update the stored login limit if the panel sent one.
    if user.max_logins is not None:
        set_user_limit(uid, user.max_logins)
    result = change_user_status_on_server(uid, user.status)
    if result:
        return ResponseModel(
            success=True,
            msg="User status changed successfully",
            data={"id": uid, "name": user.name},
        )
    return ResponseModel(success=False, msg="Failed to change user status")


@router.put("/user/limit", response_model=ResponseModel)
async def set_user_login_limit(payload: UserLimit, api_key: str = Depends(check_api_key)):
    """Set the max simultaneous logins/devices for a client (set_user_limit()).

    max_logins: 1 = single login, 0 = unlimited. ``id`` may be the numeric
    user id or the username — set_user_limit_on_all_nodes() sends the name
    when it has no user_id.
    """
    uid = validate_user_id(payload.id)
    if uid is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
    result = set_user_limit(uid, payload.max_logins)
    if result:
        return ResponseModel(
            success=True,
            msg="User login limit updated successfully",
            data={"id": uid, "name": payload.name, "max_logins": payload.max_logins},
        )
    return ResponseModel(success=False, msg="Failed to update user login limit")


@router.get("/download/ovpn/{uid}")
async def download_ovpn(uid: str, request: Request, api_key: str = Depends(check_api_key)):
    """Return the client's .ovpn profile (download_ovpn_client()/_bytes()).

    The panel validates the raw body: it must start with "client" or contain
    "<ca>" — which the generated profile always does. The client cert/config
    is created lazily here on first download (the panel intentionally does
    not create node-side users at Add User time).

    The tight cert-issuing budget is charged only on the cold path (profile
    missing → easyrsa fork); cached downloads keep the normal bucket.
    """
    safe_id = validate_user_id(uid)
    if safe_id is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
    from core.api.auth import apply_heavy_limit
    from core.openvpn import store

    if not os.path.exists(store.ovpn_path(cn_from_uid(safe_id))):
        apply_heavy_limit(request)
    # Lazy cert issuance/profile build inside this call is blocking work.
    response = await run_in_threadpool(download_ovpn_file, safe_id)
    if response:
        return FileResponse(
            path=response,
            filename=f"{uid}.ovpn",
            media_type="application/x-openvpn-profile",
        )
    # Envelope failure (not 404): the panel validates the raw body
    # (must start with "client" or contain "<ca>"), so a JSON envelope
    # safely resolves to "not found" without a transport-error log.
    return ResponseModel(success=False, msg="OVPN file not found")
