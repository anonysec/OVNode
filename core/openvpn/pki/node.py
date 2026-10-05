# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Node-local lookups: this node's address, ports, and the openvpn binary."""

import os
import shutil
import socket
import subprocess

from core.openvpn.pki import paths as _paths


def _node_public_ip() -> str:
    """This node's first non-loopback IPv4 address.

    Used when the panel has not pushed a tunnel address yet, so a generated
    .ovpn carries a usable address instead of a placeholder.
    """
    try:
        out = subprocess.run(
            ["hostname", "-I"], capture_output=True, text=True, timeout=3, check=False
        ).stdout.split()
        for addr in out:
            if not addr.startswith("127.") and ":" not in addr:
                return addr
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return "127.0.0.1"


def _remote_lines(tunnel_addr: str, primary_port: int) -> str:
    """One `remote` line per reachable port — clients fail over in order."""
    ports = [primary_port, *_paths._extra_vpn_ports()]
    return "\n".join(f"remote {tunnel_addr} {p}" for p in ports)


def _openvpn_bin() -> str:
    """Locate the openvpn binary (PATH or common locations)."""
    found = shutil.which("openvpn")
    if found:
        return found
    for candidate in ("/usr/sbin/openvpn", "/usr/local/sbin/openvpn", "/sbin/openvpn"):
        if os.path.exists(candidate):
            return candidate
    return "openvpn"  # let subprocess raise a clear error if truly absent
