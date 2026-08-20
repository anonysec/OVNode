# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

import psutil
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from core.auth.auth import check_api_key
from core.schema.all_schemas import ResponseModel, SetSettingsModel, User, UserLimit
from core.service.sessions import disconnect_user, user_diagnostics
from core.service.user_management import (
    change_user_status as change_user_status_on_server,
)
from core.service.user_management import (
    create_user_on_server,
    delete_user_on_server,
    download_ovpn_file,
    get_users_usage,
    set_user_limit,
)
from core.setting.core import change_config
from core.validation import DeleteResult, validate_user_id
from core.version import __version__

router = APIRouter(prefix="/sync", tags=["node_sync"])


@router.get("/health", include_in_schema=False)
async def health_check():
    """Simple health check endpoint - no auth required for Docker healthcheck."""
    return {"status": "ok"}


@router.get("/status", response_model=ResponseModel)
async def get_status(
    api_key: str = Depends(check_api_key),
):
    """Get the current status of the node. GET is read-only."""
    status = {"status": "running", "version": __version__}
    cpu_usage = psutil.cpu_percent(interval=None)
    memory_info = psutil.virtual_memory()
    status.update(
        {
            "cpu_usage": cpu_usage,
            "memory_usage": memory_info.percent,
        }
    )
    # TLS certificate expiry (ISO date) when the node serves HTTPS — lets the
    # panel warn before the certificate lapses and breaks node connectivity.
    status["cert_expiry"] = _cert_expiry()
    return ResponseModel(success=True, msg="Node status retrieved successfully", data=status)


def _cert_expiry() -> str | None:
    """Return the server certificate expiry as an ISO date, or None.

    Reads the configured SSL cert file and parses its notAfter value.
    Returns None when TLS is not configured or the cert is unreadable.
    """
    try:
        from core.config import settings

        cert_file = settings.ssl_certfile
        if not cert_file:
            return None
        import subprocess

        out = subprocess.run(
            ["openssl", "x509", "-enddate", "-noout", "-in", cert_file],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode != 0:
            return None
        line = out.stdout.strip()
        if not line.startswith("notAfter="):
            return None
        # OpenSSL emits RFC2822 (e.g. "Aug 12 12:00:00 2027 GMT").
        import datetime as _dt

        parsed = _dt.datetime.strptime(line[len("notAfter="):].strip(), "%b %d %H:%M:%S %Y %Z")
        return parsed.date().isoformat()
    except Exception:
        return None


@router.post("/config", response_model=ResponseModel)
async def update_config(
    request: SetSettingsModel,
    api_key: str = Depends(check_api_key),
):
    """Apply VPN configuration settings."""
    if not request.set_new_setting:
        return ResponseModel(success=True, msg="No changes requested")
    change_settings = change_config(request)
    if not change_settings:
        return ResponseModel(success=False, msg="Failed to change settings")
    return ResponseModel(success=True, msg="Configuration updated successfully")


@router.get("/usage", response_model=ResponseModel)
async def get_all_user_usage(api_key: str = Depends(check_api_key)):
    usages = get_users_usage()
    if usages:
        return ResponseModel(success=True, msg="Latest user usage received", data=usages)
    return ResponseModel(
        success=True,
        msg="No user is using it.",
    )


@router.get("/sessions", response_model=ResponseModel)
async def get_session_diagnostics(
    common_name: str | None = None,
    hours: int = 8,
    api_key: str = Depends(check_api_key),
):
    """Return live sessions, stale markers and recent max-login auth errors."""
    return ResponseModel(
        success=True,
        msg="Session diagnostics retrieved successfully",
        data=user_diagnostics(common_name=common_name, hours=hours),
    )


@router.post("/user/{uid}/disconnect", response_model=ResponseModel)
async def disconnect_user_sessions(uid: str, api_key: str = Depends(check_api_key)):
    """Best-effort disconnect for a user; also clears stale active markers."""
    from core.service.user_management import _cn_from_uid

    safe_id = validate_user_id(uid)
    if safe_id is None:
        raise HTTPException(status_code=400, detail="Invalid user id")
    cn = _cn_from_uid(safe_id)
    return ResponseModel(
        success=True,
        msg="Disconnect command processed",
        data=disconnect_user(cn),
    )


@router.post("/user", response_model=ResponseModel)
async def create_user(user: User, api_key: str = Depends(check_api_key)):
    uid = validate_user_id(user.id)
    if uid is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID)")
    max_logins = user.max_logins if user.max_logins is not None else 1
    success = create_user_on_server(uid, user.name or "", max_logins)
    if success:
        return ResponseModel(
            success=True,
            msg="User created successfully",
            data={"id": uid, "name": user.name},
        )
    return ResponseModel(success=False, msg="Failed to create user")


@router.delete("/user/{uid}", response_model=ResponseModel)
async def delete_user(uid: str, api_key: str = Depends(check_api_key)):
    safe_id = validate_user_id(uid)
    if safe_id is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID)")
    result = delete_user_on_server(safe_id)
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
    uid = validate_user_id(user.id)
    if uid is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID)")
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
    """Set the max simultaneous logins/devices for a client.

    max_logins: 1 = single login, 0 = unlimited.
    """
    uid = validate_user_id(payload.id)
    if uid is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID)")
    result = set_user_limit(uid, payload.max_logins)
    if result:
        return ResponseModel(
            success=True,
            msg="User login limit updated successfully",
            data={"id": uid, "name": payload.name, "max_logins": payload.max_logins},
        )
    return ResponseModel(success=False, msg="Failed to update user login limit")


@router.get("/download/ovpn/{uid}")
async def download_ovpn(uid: str, api_key: str = Depends(check_api_key)):
    safe_id = validate_user_id(uid)
    if safe_id is None:
        raise HTTPException(status_code=400, detail="Invalid user id")
    response = await download_ovpn_file(safe_id)
    if response:
        return FileResponse(
            path=response,
            filename=f"{uid}.ovpn",
            media_type="application/x-openvpn-profile",
        )
    raise HTTPException(status_code=404, detail="OVPN file not found")
