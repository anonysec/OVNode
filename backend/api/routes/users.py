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
    POST   /sync/renew-cert                  renew_server_cert
    POST   /sync/users                       set_user_limits (bulk)
    PUT    /sync/users/{cn}                  push_user_credentials
    PUT    /sync/pki                         push_pki

The panel treats a call as successful ONLY when the response is HTTP 200
with ``{"success": true}``, so handlers report business failures inside the
envelope instead of raising — except where the panel checks the HTTP status
itself (ovpn download must be a raw 200 body starting with "client").

Authentication: the panel sends the node API key in the ``key`` header.
"""

import os

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse

from backend.api.auth import check_api_key, check_api_key_heavy
from backend.api.routes.system import _resolve_identity
from backend.api.schemas import BulkUserLimits, ResponseModel, SyncUserCredential, User, UserLimit
from backend.openvpn.sessions import disconnect_user
from backend.openvpn.users import (
    change_user_status as change_user_status_on_server,
)
from backend.openvpn.users import (
    cn_from_uid,
    create_user_on_server,
    delete_user_on_server,
    download_ovpn_file,
    set_user_limit,
)
from backend.validation import DeleteResult, validate_user_id

router = APIRouter(prefix="/sync", tags=["node_sync"])


@router.post("/user/{uid}/disconnect", response_model=ResponseModel)
async def disconnect_user_sessions(
    uid: str, only_stale: bool = False, api_key: str = Depends(check_api_key)
):
    """Best-effort disconnect for a user; also clears stale active markers.

    `uid` is the numeric user id or a raw CN (clean_stale_sessions_all_nodes()
    forwards marker CNs verbatim). ``only_stale=True`` never kills live
    sessions — it only removes dead markers, so it is safe for users that
    also hold a healthy session.
    """
    safe_id = validate_user_id(uid)
    if safe_id is None:
        # Business failure inside the envelope: the panel treats any non-200
        # as a transport error and retries loudly.
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

    Complements delete (which also clears) — restart counting without
    revoking the certificate.
    """
    from backend.openvpn import store

    safe_id = validate_user_id(uid)
    if safe_id is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
    store.reset_usage(cn_from_uid(safe_id))
    return ResponseModel(success=True, msg="Usage counters reset", data={"id": safe_id})


@router.post("/users", response_model=ResponseModel)
async def bulk_user_limits(payload: BulkUserLimits, api_key: str = Depends(check_api_key)):
    """Apply max-login limits for many users in one call (POST /sync/users).

    The panel's limit sweep used to fan out one PUT /sync/user/limit per user
    per node — N×M requests every 30 minutes. Per-item failures land in
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


@router.put("/users/{cn}", response_model=None)
async def push_user_credentials(
    cn: str,
    payload: SyncUserCredential,
    api_key: str = Depends(check_api_key),
):
    """Store panel-pushed user credentials + state (PUT /sync/users/{cn}).

    The panel owns the PKI: it signs the user cert and pushes it here. The node
    stores it passively (no local CA/cert generation). ``state`` is always
    written; ``cert.pem``/``key.pem`` are required for a usable user, and
    ``ca.pem`` mirrors the panel CA. Idempotent — a re-push overwrites.
    """
    safe_id = validate_user_id(cn)
    if safe_id is None:
        raise HTTPException(status_code=400, detail="Invalid user id (must be UUID or simple id)")
    if not payload.cert_pem or not payload.key_pem:
        raise HTTPException(status_code=400, detail="cert_pem and key_pem are required")
    # Writing PEM + building the profile touches disk (and no easyrsa fork).
    ok = await run_in_threadpool(
        create_user_on_server,
        safe_id,
        "",
        payload.max_logins,
        payload.cert_pem,
        payload.key_pem,
        payload.ca_pem,
        payload.disabled,
    )
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to store pushed credentials")
    return {"ok": True, "success": True, "msg": "User credentials stored", "id": safe_id}


@router.post("/user", response_model=ResponseModel)
async def create_user(user: User, api_key: str = Depends(check_api_key_heavy)):
    """Create a client certificate + .ovpn (create_user()).

    ``id`` is optional: without it the normalized name is the identity.
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
        # Success, not failure: the cert is already gone, and the panel's
        # delete_user_on_all_nodes() needs all() == True to proceed with its
        # own cleanup.
        return ResponseModel(success=True, msg="User not found on node (already deleted)")
    return ResponseModel(success=False, msg="Failed to delete user")


@router.put("/user", response_model=ResponseModel)
async def change_user_status(user: User, api_key: str = Depends(check_api_key)):
    """Activate/deactivate a client (change_user_status())."""
    uid = _resolve_identity(user.id, user.name)
    if uid is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
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

    ``id`` may be the numeric user id or the username —
    set_user_limit_on_all_nodes() sends the name when it has no user_id.
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

    The panel validates the raw body (it must start with "client" or contain
    "<ca>"), so the client cert/config is created lazily here on first
    download rather than at Add User time. The tight cert-issuing budget is
    charged only on that cold path; cached downloads keep the normal bucket.
    """
    safe_id = validate_user_id(uid)
    if safe_id is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
    from backend.api.auth import apply_heavy_limit
    from backend.openvpn import store

    if not os.path.exists(store.ovpn_path(cn_from_uid(safe_id))):
        apply_heavy_limit(request)
    # Lazy cert issuance runs inside this call, so keep it off the event loop.
    response = await run_in_threadpool(download_ovpn_file, safe_id)
    if response:
        return FileResponse(
            path=response,
            filename=f"{uid}.ovpn",
            media_type="application/x-openvpn-profile",
        )
    # Envelope failure, not a 404: the panel's body check resolves the JSON
    # safely to "not found" without a transport-error log.
    return ResponseModel(success=False, msg="OVPN file not found")
