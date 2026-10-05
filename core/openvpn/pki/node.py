# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Node-local lookups: this node's address, ports, and OVNODE_* settings."""

import os
import shutil
import socket
import subprocess


def _env(name: str, default: str) -> str:
    """Read an OVNODE_* env var with a default (config.py is the source)."""
    try:
        from core.config import settings

        return str(getattr(settings, f"ovnode_{name}", default) or default)
    except Exception:
        return os.getenv(f"OVNODE_{name.upper()}", default)


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
    ports = [primary_port, *_extra_vpn_ports()]
    return "\n".join(f"remote {tunnel_addr} {p}" for p in ports)


def _openvpn_port() -> int:
    try:
        return int(os.getenv("OPENVPN_PORT", "1194"))
    except ValueError:
        return 1194


def _extra_vpn_ports() -> list[int]:
    """Extra ports the node is reachable on (iptables REDIRECT → primary)."""
    from core.config import parse_extra_ports

    return parse_extra_ports(os.getenv("OVNODE_EXTRA_PORTS", ""), _openvpn_port())


def _vpn_dns() -> tuple[str, str]:
    return _env("vpn_dns1", "1.1.1.1"), _env("vpn_dns2", "8.8.8.8")


def _openvpn_bin() -> str:
    """Locate the openvpn binary (PATH or common locations)."""
    found = shutil.which("openvpn")
    if found:
        return found
    for candidate in ("/usr/sbin/openvpn", "/usr/local/sbin/openvpn", "/sbin/openvpn"):
        if os.path.exists(candidate):
            return candidate
    return "openvpn"  # let subprocess raise a clear error if truly absent
