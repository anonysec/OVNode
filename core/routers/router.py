from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
import psutil
from core.schema.all_schemas import User, UserLimit, ResponseModel, SetSettingsModel
from core.auth.auth import check_api_key
from core.service.user_managment import (
    create_user_on_server,
    change_user_status as change_user_status_on_server,
    delete_user_on_server,
    download_ovpn_file,
    get_users_usage,
    set_user_limit,
)
from core.service.sessions import disconnect_user, user_diagnostics
from core.setting.core import change_config


router = APIRouter(prefix="/sync", tags=["node_sync"])


@router.get("/status", response_model=ResponseModel)
async def get_status(
    request: SetSettingsModel | None = None,
    api_key: str = Depends(check_api_key),
):
    """Get the current status of the node and optionally set ovpn settings."""
    if request is not None and request.set_new_setting:
        change_settings = change_config(request)
        if not change_settings:
            return ResponseModel(success=False, msg="Failed to change settings")

    status = {"status": "running"}
    cpu_usage = psutil.cpu_percent()
    memory_info = psutil.virtual_memory()
    status.update(
        {
            "cpu_usage": cpu_usage,
            "memory_usage": memory_info.percent,
        }
    )
    return ResponseModel(
        success=True, msg="Node status retrieved successfully", data=status
    )

@router.get("/usage", response_model=ResponseModel)
async def get_all_user_usage(api_key: str = Depends(check_api_key)):
    usages = get_users_usage()
    if usages:
        return ResponseModel(success=True, msg="Latest user usage received", data=usages) 
    return ResponseModel(success=True, msg="No user is using it.",)


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


@router.post("/user/{name}/disconnect", response_model=ResponseModel)
async def disconnect_user_sessions(name: str, api_key: str = Depends(check_api_key)):
    """Best-effort disconnect for a CN; also clears stale active markers."""
    return ResponseModel(
        success=True,
        msg="Disconnect command processed",
        data=disconnect_user(name),
    )


@router.post("/user", response_model=ResponseModel)
async def create_user(user: User, api_key: str = Depends(check_api_key)):
    max_logins = user.max_logins if user.max_logins is not None else 1
    success = create_user_on_server(user.name, max_logins)
    if success:
        return ResponseModel(
            success=True,
            msg="User created successfully",
            data={"client_name": user.name},
        )
    return ResponseModel(success=False, msg="Failed to create user")


@router.delete("/user/{name}", response_model=ResponseModel)
async def delete_user(name: str, api_key: str = Depends(check_api_key)):
    result = delete_user_on_server(name)
    if result:
        return ResponseModel(
            success=True,
            msg="User deleted successfully",
            data={"client_name": name},
        )
    return ResponseModel(success=False, msg="Failed to delete user")


@router.put("/user", response_model=ResponseModel)
async def change_user_status(user: User, api_key: str = Depends(check_api_key)):
    # Update the stored login limit if the panel sent one.
    if user.max_logins is not None:
        set_user_limit(user.name, user.max_logins)
    result = change_user_status_on_server(user.name, user.status)
    if result:
        return ResponseModel(
            success=True,
            msg="User status changed successfully",
            data={"client_name": user.name},
        )
    return ResponseModel(success=False, msg="Failed to change user status")


@router.put("/user/limit", response_model=ResponseModel)
async def set_user_login_limit(
    payload: UserLimit, api_key: str = Depends(check_api_key)
):
    """Set the max simultaneous logins/devices for a client.

    max_logins: 1 = single login, 0 = unlimited.
    """
    result = set_user_limit(payload.name, payload.max_logins)
    if result:
        return ResponseModel(
            success=True,
            msg="User login limit updated successfully",
            data={"client_name": payload.name, "max_logins": payload.max_logins},
        )
    return ResponseModel(success=False, msg="Failed to update user login limit")


@router.get("/download/ovpn/{client_name}")
async def download_ovpn(client_name: str, api_key: str = Depends(check_api_key)):
    response = await download_ovpn_file(client_name)
    if response:
        return FileResponse(
            path=response,
            filename=f"{client_name}.ovpn",
            media_type="application/x-openvpn-profile",
        )
    raise HTTPException(status_code=404, detail="OVPN file not found")
