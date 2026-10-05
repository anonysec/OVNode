# Copyright (c) 2026 anonysec
# SPDX-License-Identifier: MIT

"""Every path the PKI writes to, plus the OVNODE_* helpers that read them.

Leaf module: it imports nothing else from this package (config is imported
lazily), so the other submodules can depend on it without a circular import.
"""

import os

from core.openvpn.atomic import openvpn_root

_OPENVPN_ROOT = openvpn_root()
EASYRSA_DIR = os.path.join(_OPENVPN_ROOT, "server", "easy-rsa")
PKI_DIR = os.path.join(_OPENVPN_ROOT, "server", "pki")
SERVER_CONF = os.path.join(_OPENVPN_ROOT, "server", "server.conf")
CLIENT_TEMPLATE = os.path.join(_OPENVPN_ROOT, "server", "client-common.txt")
TLS_KEY = os.path.join(_OPENVPN_ROOT, "server", "tls.key")
CA_CERT = os.path.join(PKI_DIR, "ca.crt")
SERVER_CERT = os.path.join(PKI_DIR, "issued", "server.crt")
DH_PEM = os.path.join(PKI_DIR, "dh.pem")
CRL_FILE = os.path.join(PKI_DIR, "crl.pem")
PID_FILE = os.path.join(_OPENVPN_ROOT, "server", "ovnode.pid")
# Management-interface password file (0600). Localhost is shared in
# host-network mode, so the mgmt socket must require auth, not just bind.
MGMT_PASS_FILE = os.path.join(_OPENVPN_ROOT, "server", "mgmt-pass")

REQUIRED_DIRS = [
    os.path.join(_OPENVPN_ROOT, "server"),
    os.path.join(_OPENVPN_ROOT, "ccd"),
]


def _env(name: str, default: str) -> str:
    """Read an OVNODE_* env var with a default (config.py is the source)."""
    try:
        from core.config import settings

        return str(getattr(settings, f"ovnode_{name}", default) or default)
    except Exception:
        return os.getenv(f"OVNODE_{name.upper()}", default)


def _openvpn_port() -> int:
    try:
        return int(os.getenv("OPENVPN_PORT", "1194"))
    except ValueError:
        return 1194


def _extra_vpn_ports() -> list[int]:
    """Extra ports the node is reachable on (iptables REDIRECT → primary)."""
    from core.config import parse_extra_ports

    return parse_extra_ports(os.getenv("OVNODE_EXTRA_PORTS", ""), _openvpn_port())
