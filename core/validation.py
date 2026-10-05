# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Input validation for node-facing API parameters.

OpenVPN's client identity is the certificate Common Name (CN), which the node
stores on disk as /etc/openvpn/ccd/<name>, /etc/openvpn/limits/<name> and
/etc/openvpn/clients/<name>.ovpn, and feeds to the interactive installer via
pexpect. The panel sends a stable `id` (UUID or simple numeric/alphanumeric
ID) which becomes that identity and is validated by validate_user_id() before
it touches disk or a child process; the store re-checks it with _safe_cn().
"""

from __future__ import annotations

import enum
import re
import uuid

# OpenVPN CNs are conventionally alphanumeric; a few safe separators are
# allowed on top. Keep this strict — it is the only thing that ever reaches a
# filename or the pexpect child process.
_CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,32}$")

# A UUID (with or without dashes). The panel generates these.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$"
)

# Simple numeric or alphanumeric ID (panel may use auto-increment ints or short strings)
_SIMPLE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class DeleteResult(enum.Enum):
    OK = "ok"
    NOT_FOUND = "not_found"
    FAILED = "failed"


def validate_user_id(uid: str | None) -> str | None:
    """Return `uid` if it is a well-formed UUID or simple ID, else None."""
    if not uid or not isinstance(uid, str):
        return None
    if _UUID_RE.match(uid):
        try:
            return str(uuid.UUID(uid))
        except (ValueError, AttributeError, TypeError):
            return None
    if _SIMPLE_ID_RE.match(uid):
        return uid
    return None
