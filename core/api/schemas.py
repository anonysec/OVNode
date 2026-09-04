# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Request/response schemas for the OVManager ⇄ OVNode sync API.

These models mirror the payloads built by OVManager's
``backend/node/requests.py`` (class ``NodeRequests``) exactly:

* ``create_user``        → POST /sync/user      {"name", "max_logins", "id"?}
* ``change_user_status`` → PUT  /sync/user      {"name", "status", "id"?, "max_logins"?}
* ``set_user_limit``     → PUT  /sync/user/limit {"id", "max_logins"}
* ``update_config``      → POST /sync/config    {"tunnel_address", "protocol",
                                                 "ovpn_port", "set_new_setting"}

Every response is wrapped in ``ResponseModel`` — the panel's ``_request()``
helper requires HTTP 200 **and** ``success: true`` to treat a call as OK.
"""

from typing import Any, Literal

from pydantic import BaseModel, Field


class User(BaseModel):
    # Stable panel-side user id (numeric DB id as a string, or a UUID).
    # This IS the OpenVPN client identity (CN) when present. The panel may
    # omit it (NodeRequests.create_user only includes "id" when truthy), in
    # which case the node falls back to the normalized display name.
    id: str | None = None
    # Display name / panel username. Not the OpenVPN identity when `id` is set,
    # but stored so usage reports can be keyed by username for the panel's
    # traffic collector (_extract_username → all_users[u.name]).
    name: str | None = None
    # "activate" | "deactivate" — matches NodeRequests.change_user_status().
    status: Literal["activate", "deactivate"] = "activate"
    # Max simultaneous logins/devices: 1 = single login (takeover),
    # 0 = unlimited, N>1 = strict cap. Mirrors the panel's user.max_logins.
    # Ranged: a negative value previously coerced to 0 (unlimited) silently.
    max_logins: int | None = Field(default=1, ge=0, le=1000)


class UserLimit(BaseModel):
    # May be the numeric user id OR the username — the panel's
    # set_user_limit_on_all_nodes() sends the name when no user_id is known.
    id: str
    name: str | None = None
    max_logins: int = Field(default=1, ge=0, le=1000)


class ResponseModel(BaseModel):
    success: bool
    msg: str
    data: Any | None = None


class SetSettingsModel(BaseModel):
    tunnel_address: str
    # Unknown values previously fell through to udp silently in
    # change_config — reject them so panel misconfigurations surface.
    protocol: Literal["tcp", "udp"]
    ovpn_port: int = Field(ge=1, le=65535)
    set_new_setting: bool


class UsersUsage(BaseModel):
    # Per-user total bytes. Keys are panel usernames when known (the panel's
    # traffic collector looks rows up by username), falling back to the CN.
    users: dict[str, float]
    # Per-session bytes: {key: {"ip:port": bytes}}. Contains BOTH the CN key
    # (consumed by the panel's /mlogin global registry, which maps numeric-id
    # CNs to usernames) and the username key (consumed by the traffic
    # collector's per-session delta path).
    sessions: dict[str, dict[str, float]] = {}
