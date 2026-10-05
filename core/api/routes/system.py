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

The panel treats a call as successful ONLY when the response is HTTP 200
with ``{"success": true}``, so handlers report business failures inside the
envelope instead of raising — except where the panel checks the HTTP status
itself (ovpn download must be a raw 200 body starting with "client").

Authentication: the panel sends the node API key in the ``key`` header.
"""

import os
import subprocess
import time

import psutil
from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool

from core.api.auth import check_api_key
from core.api.schemas import ResponseModel
from core.logger import log_stats, recent_logs
from core.validation import validate_user_id
from core.version import __version__

router = APIRouter(prefix="/sync", tags=["node_sync"])

_STARTED_AT = time.monotonic()

# _ensure_crl() forks openssl, too heavy for every /sync/status poll — but a
# boot-only check risks a total client lockout once the CRL lapses after
# >1yr of uptime and crl-verify starts rejecting everyone.
_CRL_CHECK_INTERVAL = 86400.0
_crl_last_check = 0.0


def _ensure_crl_fresh_sync() -> None:
    """Blocking half: may fork ``easyrsa gen-crl``. Never call this inline."""
    global _crl_last_check
    now = time.monotonic()
    if now - _crl_last_check < _CRL_CHECK_INTERVAL:
        return
    _crl_last_check = now
    try:
        from core.openvpn.pki.certs import _ensure_crl

        _ensure_crl()
    except Exception:
        # Best-effort: renewal failures are already logged inside pki.
        pass


async def _ensure_crl_fresh() -> None:
    """Daily CRL freshness check, off the event loop.

    The easyrsa fork can take 120s; inline from the async route it stalls the
    single uvicorn worker and every other panel call queues behind it.
    """
    await run_in_threadpool(_ensure_crl_fresh_sync)


def _resolve_identity(uid: str | None, name: str | None) -> str | None:
    """Resolve the OpenVPN client identity from a panel payload.

    The panel may omit ``id``, in which case the normalized username becomes
    the identity — mirroring the panel's own ``name.replace(" ", "_")``.
    """
    if uid:
        return validate_user_id(uid)
    if name:
        return validate_user_id(name.strip().replace(" ", "_"))
    return None


@router.get("/health", include_in_schema=False)
async def health_check():
    """Docker healthcheck probe — no auth, so the container can poll it."""
    return {"status": "ok"}


@router.get("/status", response_model=ResponseModel)
async def get_status(
    request: Request,
    api_key: str = Depends(check_api_key),
):
    """Node status — consumed by check_node()/get_node_info().

    The panel reads ``cpu_usage``, ``memory_usage`` and ``cert_expiry`` from
    ``data``; the remaining keys are additive diagnostics (panels ignore
    unknown keys) so node health is visible without SSH.
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
    # TLS cert expiry, so the panel can warn before connectivity breaks.
    status["cert_expiry"] = _cert_expiry()
    # VPN PKI expiries (CA 10y, server 5y): a lapsed CA or server cert
    # silently kills every client and the panel cannot see them otherwise.
    status["ca_expiry"], status["server_expiry"] = _pki_expiry()
    await _ensure_crl_fresh()
    return ResponseModel(success=True, msg="Node status retrieved successfully", data=status)


@router.get("/logs", response_model=ResponseModel)
async def get_logs(
    level: str = "WARNING",
    limit: int = 200,
    api_key: str = Depends(check_api_key),
):
    """Recent node log records (in-memory ring buffer) — remote diagnostics.

    Read by the panel's node log viewer; also usable by hand:

        curl -H "key: $API_KEY" https://node:2083/sync/logs?level=ERROR
    """
    records = recent_logs(min_level=level, limit=limit)
    return ResponseModel(
        success=True,
        msg=f"{len(records)} log record(s)",
        data={"records": records, **log_stats()},
    )


# An openssl fork per call is too heavy for the /sync/status cadence, but a
# cert lasts years — a manual replacement shows up within 24h.
_CERT_EXPIRY_TTL = 86400.0
_cert_expiry_cached: str | None = None
_cert_expiry_checked_at = 0.0


def _cert_expiry() -> str | None:
    """Server TLS certificate notAfter as an ISO date, or None when unreadable."""
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
        return _openssl_enddate(cert_file)
    except Exception:
        return None


def _openssl_enddate(cert_file: str) -> str | None:
    """Parse a PEM cert's notAfter into an ISO date (one openssl fork)."""
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


_pki_expiry_cached: tuple[str | None, str | None] | None = None
_pki_expiry_checked_at = 0.0


def _pki_expiry() -> tuple[str | None, str | None]:
    """(ca_expiry, server_expiry) ISO dates, cached like the TLS one."""
    global _pki_expiry_cached, _pki_expiry_checked_at
    now = time.monotonic()
    if _pki_expiry_cached is not None and now - _pki_expiry_checked_at < _CERT_EXPIRY_TTL:
        return _pki_expiry_cached
    try:
        from core.openvpn.pki import CA_CERT, SERVER_CERT

        result = (
            _openssl_enddate(CA_CERT) if os.path.exists(CA_CERT) else None,
            _openssl_enddate(SERVER_CERT) if os.path.exists(SERVER_CERT) else None,
        )
    except Exception:
        result = (None, None)
    _pki_expiry_cached = result
    _pki_expiry_checked_at = now
    return result
