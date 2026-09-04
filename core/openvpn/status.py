# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""OpenVPN status-file parser (status-version 2/3).

Header-aware: column positions are resolved from the ``HEADER,CLIENT_LIST``
line, so the parser works across OpenVPN versions (2.3 lacked the Virtual
IPv6 column that shifts every later field). Falls back to the modern layout
when no header is present.

Session identity note: most deployments here serve dynamic-IP users, so the
stable per-session identifiers are the *virtual address* (VPN pool IP,
unique per session under duplicate-cn) and the *client id* (management
CID) — NOT the client's real IP:port, which changes on every reconnect.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator

logger = logging.getLogger("ovnode")

_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
STATUS_FILE = os.getenv("OVNODE_STATUS_FILE", os.path.join(_OPENVPN_ROOT, "server", "status.log"))

# Modern (OpenVPN >= 2.4) CLIENT_LIST columns, used when no HEADER line exists.
_DEFAULT_COLUMNS = {
    "Common Name": 1,
    "Real Address": 2,
    "Virtual Address": 3,
    "Bytes Received": 5,
    "Bytes Sent": 6,
    "Client ID": 10,
}


def _split_real_address(real_address: str) -> tuple[str, str]:
    """Split "ip:port" (IPv6-bracket aware) into (ip, port)."""
    if not real_address:
        return "", ""
    if ":" in real_address:
        ip, port = real_address.rsplit(":", 1)
        return ip.strip("[]"), port
    return real_address, ""


def _column_map(header_parts: list[str]) -> dict[str, int]:
    """Resolve column name → index from a HEADER,CLIENT_LIST,... line."""
    columns = dict(_DEFAULT_COLUMNS)
    # header_parts[0] == "HEADER", [1] == "CLIENT_LIST", data rows have no
    # "HEADER" prefix — so a data field N corresponds to header index N + 1.
    for idx, name in enumerate(header_parts[2:]):
        if name in columns:
            columns[name] = idx + 1
    return columns


def iter_sessions(path: str = STATUS_FILE) -> Iterator[dict]:
    """Yield one dict per connected client from the status file."""
    if not os.path.exists(path):
        return
    columns = dict(_DEFAULT_COLUMNS)
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                delim = "\t" if "\t" in line else ","
                if line.startswith("HEADER") and "CLIENT_LIST" in line:
                    columns = _column_map(line.split(delim))
                    continue
                if not line.startswith("CLIENT_LIST"):
                    continue
                parts = line.split(delim)
                cn = _field(parts, columns["Common Name"])
                if not cn or cn == "Common Name":
                    continue
                real = _field(parts, columns["Real Address"])
                ip, port = _split_real_address(real)
                yield {
                    "common_name": cn,
                    "real_address": real,
                    "trusted_ip": ip,
                    "trusted_port": port,
                    "virtual_address": _field(parts, columns["Virtual Address"]),
                    "bytes_received": _int(_field(parts, columns["Bytes Received"])),
                    "bytes_sent": _int(_field(parts, columns["Bytes Sent"])),
                    "client_id": _field(parts, columns["Client ID"]),
                }
    except OSError as e:
        logger.error("Failed to read status file %s: %s", path, e)


def _field(parts: list[str], idx: int) -> str:
    return parts[idx].strip() if idx < len(parts) else ""


def _int(value: str) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def parse_usage(path: str = STATUS_FILE) -> dict | None:
    """→ {"users": {cn: bytes}, "sessions": {cn: {real_addr: bytes}}}. None if empty."""
    users: dict[str, int] = {}
    sessions: dict[str, dict[str, int]] = {}
    for s in iter_sessions(path):
        total = s["bytes_received"] + s["bytes_sent"]
        cn = s["common_name"]
        users[cn] = users.get(cn, 0) + total
        sessions.setdefault(cn, {})[s["real_address"]] = total
    return {"users": users, "sessions": sessions} if users else None


def parse_sessions(path: str = STATUS_FILE) -> list[dict]:
    """→ list of session dicts (cn, addresses, counters, client id)."""
    return list(iter_sessions(path))
