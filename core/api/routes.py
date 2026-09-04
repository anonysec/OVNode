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
    POST   /sync/user                        create_user
    PUT    /sync/user                        change_user_status
    PUT    /sync/user/limit                  set_user_limit
    DELETE /sync/user/{uid}                  delete_user
    POST   /sync/user/{uid}/disconnect       disconnect_user
    GET    /sync/download/ovpn/{uid}         download_ovpn_client / _bytes

The panel treats a call as successful ONLY when the response is HTTP 200
with ``{"success": true}`` — so handlers report business failures inside the
envelope instead of raising, except where the panel explicitly checks the
HTTP status (ovpn download must be a raw 200 body starting with "client").

Authentication: the panel sends the node API key in the ``key`` header.
"""

import time

import psutil
from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse

from core.api.auth import check_api_key
from core.api.schemas import ResponseModel, SetSettingsModel, User, UserLimit
from core.logger import log_stats, recent_logs
from core.openvpn.control import change_config
from core.openvpn.sessions import disconnect_user, user_diagnostics
from core.openvpn.users import (
    change_user_status as change_user_status_on_server,
)
from core.openvpn.users import (
    cn_from_uid,
    create_user_on_server,
    delete_user_on_server,
    download_ovpn_file,
    get_users_usage,
    set_user_limit,
)
from core.validation import DeleteResult, validate_user_id
from core.version import __version__

router = APIRouter(prefix="/sync", tags=["node_sync"])

_STARTED_AT = time.monotonic()

# CRL freshness is re-checked at most once a day: _ensure_crl() forks
# openssl, which is too heavy for every /sync/status poll, but checking
# only at boot risks a total client lockout after >1yr of uptime when the
# CRL lapses and crl-verify starts rejecting everyone.
_CRL_CHECK_INTERVAL = 86400.0
_crl_last_check = 0.0


def _ensure_crl_fresh() -> None:
    global _crl_last_check
    now = time.monotonic()
    if now - _crl_last_check < _CRL_CHECK_INTERVAL:
        return
    _crl_last_check = now
    try:
        from core.openvpn.pki import _ensure_crl

        _ensure_crl()
    except Exception:
        # Best-effort: renewal failures are already logged inside pki.
        pass


def _resolve_identity(uid: str | None, name: str | None) -> str | None:
    """Resolve the OpenVPN client identity from a panel payload.

    The panel prefers the numeric user id (``NodeRequests`` includes ``id``
    whenever it is known) but may omit it, in which case the normalized
    username becomes the identity — mirroring the panel's own
    ``request.name.replace(" ", "_")`` normalization.
    """
    if uid:
        return validate_user_id(uid)
    if name:
        return validate_user_id(name.strip().replace(" ", "_"))
    return None


@router.get("/health", include_in_schema=False)
async def health_check():
    """Simple health check endpoint - no auth required for Docker healthcheck."""
    return {"status": "ok"}


@router.get("/status", response_model=ResponseModel)
async def get_status(
    request: Request,
    api_key: str = Depends(check_api_key),
):
    """Node status — consumed by check_node()/get_node_info().

    The panel frontend (NodeDrawer/NodeTable) and metrics snapshots read
    ``cpu_usage``, ``memory_usage`` and ``cert_expiry`` from ``data``.
    The remaining keys are additive diagnostics (current panels ignore
    unknown keys): OpenVPN liveness, agent uptime and log-error counters,
    so node health is visible from the panel side without SSH.
    """
    from core.openvpn.control import openvpn_is_running

    status = {"status": "running", "version": __version__}
    degraded = getattr(getattr(request, "app", None), "state", None)
    degraded = getattr(degraded, "degraded", None) if degraded else None
    status["pki_healthy"] = degraded is None
    if degraded:
        status["degraded"] = str(degraded)
        status["status"] = "degraded"
    cpu_usage = psutil.cpu_percent(interval=None)
    memory_info = psutil.virtual_memory()
    status.update(
        {
            "cpu_usage": cpu_usage,
            "memory_usage": memory_info.percent,
            "openvpn_running": openvpn_is_running(),
            "uptime_seconds": int(time.monotonic() - _STARTED_AT),
        }
    )
    status.update(log_stats())
    # TLS certificate expiry (ISO date) when the node serves HTTPS — lets the
    # panel warn before the certificate lapses and breaks node connectivity.
    status["cert_expiry"] = _cert_expiry()
    _ensure_crl_fresh()
    return ResponseModel(success=True, msg="Node status retrieved successfully", data=status)


@router.get("/logs", response_model=ResponseModel)
async def get_logs(
    level: str = "WARNING",
    limit: int = 200,
    api_key: str = Depends(check_api_key),
):
    """Recent node log records (in-memory ring buffer) — remote diagnostics.

    Not consumed by the current panel; exists so an operator (or a future
    panel version) can inspect a node's errors without SSH:

        curl -H "key: $API_KEY" https://node:2083/sync/logs?level=ERROR
    """
    records = recent_logs(min_level=level, limit=limit)
    return ResponseModel(
        success=True,
        msg=f"{len(records)} log record(s)",
        data={"records": records, **log_stats()},
    )


# openssl fork per call is too heavy for a /sync/status poll cadence, but a
# cert lasts months — cache briefly (same idea as the CRL daily check).
_CERT_EXPIRY_TTL = 300.0
_cert_expiry_cached: str | None = None
_cert_expiry_checked_at = 0.0


def _cert_expiry() -> str | None:
    """Return the server certificate expiry as an ISO date, or None.

    Reads the configured SSL cert file and parses its notAfter value.
    Returns None when TLS is not configured or the cert is unreadable.
    """
    global _cert_expiry_cached, _cert_expiry_checked_at
    now = time.monotonic()
    if now - _cert_expiry_checked_at < _CERT_EXPIRY_TTL:
        return _cert_expiry_cached
    _cert_expiry_cached = _read_cert_expiry()
    _cert_expiry_checked_at = now
    return _cert_expiry_cached


def _read_cert_expiry() -> str | None:
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

        parsed = _dt.datetime.strptime(line[len("notAfter=") :].strip(), "%b %d %H:%M:%S %Y %Z")
        return parsed.date().isoformat()
    except Exception:
        return None


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


@router.post("/user/{uid}/disconnect", response_model=ResponseModel)
async def disconnect_user_sessions(uid: str, api_key: str = Depends(check_api_key)):
    """Best-effort disconnect for a user; also clears stale active markers.

    The panel passes either the numeric user id or a raw CN here
    (clean_stale_sessions_all_nodes() forwards marker CNs verbatim).
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
        data=disconnect_user(cn),
    )


@router.post("/user", response_model=ResponseModel)
async def create_user(user: User, api_key: str = Depends(check_api_key)):
    """Create a client certificate + .ovpn (create_user()).

    ``id`` is optional — NodeRequests only includes it when the panel knows
    the numeric user id. Without it the normalized name is the identity.
    """
    uid = _resolve_identity(user.id, user.name)
    if uid is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
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
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
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
async def download_ovpn(uid: str, api_key: str = Depends(check_api_key)):
    """Return the client's .ovpn profile (download_ovpn_client()/_bytes()).

    The panel validates the raw body: it must start with "client" or contain
    "<ca>" — which the generated profile always does. The client cert/config
    is created lazily here on first download (the panel intentionally does
    not create node-side users at Add User time).
    """
    safe_id = validate_user_id(uid)
    if safe_id is None:
        return ResponseModel(success=False, msg="Invalid user id (must be UUID or simple id)")
    response = await download_ovpn_file(safe_id)
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
