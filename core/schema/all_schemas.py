from pydantic import BaseModel
from typing import Any, Optional, Dict


class User(BaseModel):
    name: str
    status: str = "activate"
    # Max simultaneous logins/devices for this config.
    # 1 = single login (default), 0 = unlimited.
    max_logins: int = 1


class UserLimit(BaseModel):
    name: str
    max_logins: int = 1


class ResponseModel(BaseModel):
    success: bool
    msg: str
    data: Optional[Any] = None


class SetSettingsModel(BaseModel):
    tunnel_address: str
    protocol: str
    ovpn_port: int
    set_new_setting: bool

class UsersUsage(BaseModel):
    # Per-CN total bytes (kept for backward compatibility).
    users: Dict[str, float]
    # Per-session bytes: {common_name: {session_key: bytes}}. Lets the panel
    # diff each session independently so a single session disconnecting does
    # not look like a counter reset and get double-counted.
    sessions: Dict[str, Dict[str, float]] = {}