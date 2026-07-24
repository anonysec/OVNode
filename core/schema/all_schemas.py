from typing import Any

from pydantic import BaseModel


class User(BaseModel):
    # Stable panel-side user id (UUID). This IS the OpenVPN client identity.
    # All server-side paths (ccd, certs, limits, .ovpn) are keyed by this id.
    id: str
    # Optional display name / label. Not used for OpenVPN identity.
    name: str | None = None
    status: str = "activate"
    # Max simultaneous logins/devices for this config.
    # 1 = single login (default), 0 = unlimited.
    max_logins: int = 1


class UserLimit(BaseModel):
    id: str
    name: str | None = None
    max_logins: int = 1


class ResponseModel(BaseModel):
    success: bool
    msg: str
    data: Any | None = None


class SetSettingsModel(BaseModel):
    tunnel_address: str
    protocol: str
    ovpn_port: int
    set_new_setting: bool


class UsersUsage(BaseModel):
    # Per-CN total bytes (kept for backward compatibility).
    users: dict[str, float]
    # Per-session bytes: {common_name: {session_key: bytes}}. Lets the panel
    # diff each session independently so a single session disconnecting does
    # not look like a counter reset and get double-counted.
    sessions: dict[str, dict[str, float]] = {}
