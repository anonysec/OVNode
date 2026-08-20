# Copyright (c) 2025 anonysec. All rights reserved.
# Proprietary and confidential. Unauthorized copying, distribution, or use is prohibited.

"""Parse OpenVPN status file (version 2/3). Two functions. That's it."""

import logging
import os

logger = logging.getLogger("ovnode")
_OPENVPN_ROOT = os.getenv("OVNODE_OPENVPN_ROOT", "/etc/openvpn")
STATUS_FILE = os.getenv("OVNODE_STATUS_FILE", os.path.join(_OPENVPN_ROOT, "server", "status.log"))


def _iter_client_lines(path: str):
    """Yield parsed CLIENT_LIST tuples: (cn, real_addr, virt_addr, rx, tx)."""
    if not os.path.exists(path):
        return
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line.startswith("CLIENT_LIST"):
                    continue
                delim = "\t" if "\t" in line else ","
                parts = line.split(delim)
                if len(parts) < 7 or parts[1] in ("Common Name", "HEADER"):
                    continue
                try:
                    yield parts[1], parts[2], parts[3], int(parts[4] or 0), int(parts[5] or 0)
                except (ValueError, IndexError):
                    continue
    except Exception as e:
        logger.error("Failed to read status file: %s", e)


def parse_usage(path: str = STATUS_FILE) -> dict | None:
    """Parse → {"users": {cn: bytes}, "sessions": {cn: {addr: bytes}}}. None if empty."""
    users: dict[str, int] = {}
    sessions: dict[str, dict[str, int]] = {}
    for cn, addr, _, rx, tx in _iter_client_lines(path):
        total = rx + tx
        users[cn] = users.get(cn, 0) + total
        sessions.setdefault(cn, {})[addr] = total
    return {"users": users, "sessions": sessions} if users else None


def parse_sessions(path: str = STATUS_FILE) -> list[dict]:
    """Parse → list of session dicts with cn, real_address, ip, port."""
    results = []
    for cn, real_addr, virt_addr, rx, tx in _iter_client_lines(path):
        ip, port = real_addr.rsplit(":", 1) if ":" in real_addr else (real_addr, "")
        results.append(
            {
                "common_name": cn,
                "real_address": real_addr,
                "trusted_ip": ip.strip("[]"),
                "trusted_port": port,
                "virtual_address": virt_addr,
                "bytes_received": rx,
                "bytes_sent": tx,
            }
        )
    return results
