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
from fastapi.concurrency import run_in_threadpool

from core.api.auth import check_api_key, check_api_key_heavy
from core.api.routes.system import _openssl_enddate
from core.api.schemas import ResponseModel, SetSettingsModel
from core.logger import logger
from core.openvpn.control import change_config

router = APIRouter(prefix="/sync", tags=["node_sync"])


@router.get("/config", response_model=ResponseModel)
async def get_config(api_key: str = Depends(check_api_key)):
    """Live VPN endpoint settings — lets the panel detect drift.

    Additive (no panel method reads it yet): compares port/proto/tunnel
    against what the panel last pushed via POST /sync/config.
    """
    from core.openvpn.control import read_config

    data = read_config()
    return ResponseModel(success=True, msg="Configuration retrieved successfully", data=data)


@router.post("/config", response_model=ResponseModel)
async def update_config(
    request: SetSettingsModel,
    api_key: str = Depends(check_api_key),
):
    """Apply VPN endpoint settings pushed by the panel (update_config())."""
    if not request.set_new_setting:
        return ResponseModel(success=True, msg="No changes requested")
    change_settings = change_config(request)
    if not change_settings:
        return ResponseModel(success=False, msg="Failed to change settings")
    return ResponseModel(success=True, msg="Configuration updated successfully")


@router.post("/update", response_model=ResponseModel)
async def update_node_software(api_key: str = Depends(check_api_key_heavy)):
    """Trigger the node's self-update (POST /sync/update, trigger_update()).

    Native installs launch ``install.sh update --json`` detached and answer
    immediately; Docker nodes refuse (the host owns the container image).
    Heavy-limited: an update restarts the agent, so a hot loop must not
    queue them.
    """
    from core.updater import trigger_update

    return ResponseModel(**trigger_update())


@router.post("/restart", response_model=ResponseModel)
async def restart_openvpn_service(api_key: str = Depends(check_api_key_heavy)):
    """Restart/reload OpenVPN (POST /sync/restart, restart_vpn()).

    Reports failures inside the contract envelope instead of raising, so a
    broken OpenVPN — or a failing service manager — never takes this API down
    with it. ``data.openvpn_running`` is the liveness check performed *after*
    the restart attempt. Heavy-limited: a restart briefly bounces tunnels, so
    a hot panel loop must not queue them.
    """
    from core.openvpn.control import openvpn_is_running, restart_openvpn

    try:
        restarted = bool(await run_in_threadpool(restart_openvpn))
        error = ""
    except Exception as e:
        restarted = False
        error = str(e)
        logger.error("Panel-triggered OpenVPN restart failed: %s", e, exc_info=e)
    try:
        running = bool(await run_in_threadpool(openvpn_is_running))
    except Exception as e:
        running = False
        logger.warning("Could not determine OpenVPN liveness: %s", e)
    if restarted:
        return ResponseModel(
            success=True,
            msg="OpenVPN restart command completed",
            data={"openvpn_running": running},
        )
    msg = f"OpenVPN restart failed: {error}" if error else "OpenVPN restart failed"
    return ResponseModel(success=False, msg=msg, data={"openvpn_running": running})


@router.post("/renew-cert", response_model=ResponseModel)
async def renew_server_cert(api_key: str = Depends(check_api_key_heavy)):
    """Renew the OpenVPN server certificate, then restart OpenVPN.

    Used by the panel when the server certificate is close to expiry. The old
    certificate is archived by easyrsa; connected clients reconnect after the
    restart.
    """
    from core.openvpn.control import restart_openvpn
    from core.openvpn.pki import SERVER_CERT, renew_server_certificate

    renewed = bool(await run_in_threadpool(renew_server_certificate))
    if not renewed:
        return ResponseModel(
            success=False,
            msg="Server certificate renewal failed — check the node logs",
        )
    restarted = bool(await run_in_threadpool(restart_openvpn))
    if not restarted:
        return ResponseModel(
            success=False,
            msg="Certificate renewed, but OpenVPN did not restart — restart it manually",
        )
    expiry = await run_in_threadpool(_openssl_enddate, SERVER_CERT)
    return ResponseModel(
        success=True,
        msg="Server certificate renewed; OpenVPN restarted",
        data={"server_expiry": expiry},
    )
